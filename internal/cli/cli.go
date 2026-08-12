// Package cli implements the GoPassGen command line.
//
// Run returns an exit code instead of calling os.Exit, so every path is
// testable. stdout carries generated output only; diagnostics go to stderr.
package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"gopassgen/internal/bip39"
	"gopassgen/internal/buildinfo"
	"gopassgen/internal/derive"
	"gopassgen/internal/logx"
	"gopassgen/internal/passgen"
)

// Exit codes.
const (
	// ExitOK signals success.
	ExitOK = 0
	// ExitError signals a runtime failure (invalid mnemonic, I/O error, ...).
	ExitError = 1
	// ExitUsage signals a malformed or contradictory command line.
	ExitUsage = 2
	// ExitInterrupted signals SIGINT/SIGTERM during a batch.
	ExitInterrupted = 130
)

// Limits mirroring pypassgen.py.
const (
	maxNumPhrases          = 100
	maxMnemonicOnlyCount   = 10_000
	bigCountRequiresOutput = 1_000
	outputFileMode         = 0o600 // secrets: owner-only, unlike Python's 0644
)

const banner = `  ____       ____                 ____
 / ___| ___ |  _ \ __ _ ___ ___  / ___| ___ _ __
| |  _ / _ \| |_) / _` + "`" + ` / __/ __| | |  _ / _ \ '_ \
| |_| | (_) |  __/ (_| \__ \__ \ | |_| |  __/ | | |
 \____|\___/|_|   \__,_|___/___/  \____|\___|_| |_|`

// options is the parsed command line.
type options struct {
	mnemonic       string
	mnemonicStdin  bool
	autoGen        bool
	mnemonicOnly   bool
	count          int
	phrases        int
	words          int
	passwordLength int
	language       string
	output         string
	jobs           int
	verbose        bool
	logLevel       string
	logFormat      string
	noColor        bool
	selfTest       bool
	showVersion    bool

	// set records which flags the user passed explicitly. It reproduces the
	// Python "is None" checks: -count 0 must be an error, not a fallback.
	set map[string]bool
}

func (o *options) wasSet(name string) bool { return o.set[name] }

// usageError marks a command line problem, which exits with ExitUsage.
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func usagef(format string, args ...any) error {
	return usageError{fmt.Errorf(format, args...)}
}

// Run executes the CLI and returns a process exit code.
// It installs a SIGINT/SIGTERM handler so long batches abort cleanly.
func Run(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return RunContext(ctx, args, os.Stdin, stdout, stderr)
}

// RunContext is Run with caller-supplied context and stdin. Tests use it to
// exercise every path without touching process state.
func RunContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, fs, err := parse(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		fmt.Fprintf(stderr, "error: %v\n\n", err)
		fs.Usage()
		return ExitUsage
	}

	level := slog.LevelInfo
	if opts.logLevel != "" {
		level, err = logx.ParseLevel(opts.logLevel)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return ExitUsage
		}
	}
	if opts.verbose && level > slog.LevelDebug {
		level = slog.LevelDebug
	}

	format, err := logx.ParseFormat(opts.logFormat)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return ExitUsage
	}

	log := logx.New(stderr, logx.Options{
		Level:  level,
		Format: format,
		Color:  logx.ColorEnabled(stderr, opts.noColor),
	})

	err = run(ctx, opts, stdin, stdout, log)
	if err == nil {
		return ExitOK
	}

	var ue usageError
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		log.Warn("interrupted")
		return ExitInterrupted
	case errors.As(err, &ue):
		log.Error("invalid usage", slog.String("error", err.Error()))
		fs.Usage()
		return ExitUsage
	default:
		log.Error("failed", slog.String("error", err.Error()))
		return ExitError
	}
}

func parse(args []string, stderr io.Writer) (*options, *flag.FlagSet, error) {
	opts := &options{}
	fs := flag.NewFlagSet("gopassgen", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.StringVar(&opts.mnemonic, "mnemonic", "", "BIP-39 mnemonic phrase to derive a password from")
	fs.BoolVar(&opts.mnemonicStdin, "mnemonic-stdin", false, "read the mnemonic from stdin (keeps it out of shell history and ps)")
	fs.BoolVar(&opts.autoGen, "auto-gen", false, "generate mnemonic+password pairs")
	fs.BoolVar(&opts.mnemonicOnly, "mnemonic-only", false, "generate mnemonics only, no passwords")
	fs.IntVar(&opts.count, "count", 0, fmt.Sprintf("number of mnemonics for -mnemonic-only (default 1, max %d)", maxMnemonicOnlyCount))
	fs.IntVar(&opts.phrases, "phrases", 1, fmt.Sprintf("number of pairs for -auto-gen (max %d)", maxNumPhrases))
	fs.IntVar(&opts.words, "words", 12, fmt.Sprintf("words per phrase %v", bip39.WordCounts()))
	fs.IntVar(&opts.passwordLength, "password-length", derive.DefaultPasswordLength, fmt.Sprintf("password length (max %d)", derive.MaxPasswordLength))
	fs.StringVar(&opts.language, "language", "english", "wordlist language "+strings.Join(bip39.Languages(), "|"))
	fs.StringVar(&opts.output, "output", "", "write results to this file (created with mode 0600)")
	fs.IntVar(&opts.jobs, "jobs", 0, "parallel derivations (default: number of CPUs)")
	fs.BoolVar(&opts.verbose, "v", false, "shorthand for -log-level debug")
	fs.BoolVar(&opts.verbose, "verbose", false, "shorthand for -log-level debug")
	fs.StringVar(&opts.logLevel, "log-level", "", "silent|error|warn|info|debug (default info)")
	fs.StringVar(&opts.logFormat, "log-format", "", "pretty|json (default pretty)")
	fs.BoolVar(&opts.noColor, "no-color", false, "disable ANSI colour in logs")
	fs.BoolVar(&opts.selfTest, "self-test", false, "run built-in known-answer tests and exit")
	fs.BoolVar(&opts.showVersion, "version", false, "print version and exit")

	fs.Usage = func() { printUsage(stderr, fs) }

	if err := fs.Parse(args); err != nil {
		return opts, fs, err
	}
	opts.set = make(map[string]bool, fs.NFlag())
	fs.Visit(func(f *flag.Flag) { opts.set[f.Name] = true })

	if fs.NArg() > 0 {
		return opts, fs, usagef("unexpected positional argument %q (did you forget to quote the mnemonic?)", fs.Arg(0))
	}
	return opts, fs, nil
}

func printUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(w, "%s  v%s\n\n", banner, buildinfo.Version)
	fmt.Fprintf(w, "Deterministic passwords from BIP-39 mnemonic phrases.\n")
	fmt.Fprintf(w, "Bit-compatible with PyPassGen %s.\n\n", buildinfo.DerivationVersion)
	fmt.Fprintf(w, "Usage:\n  gopassgen -mnemonic \"word1 ... word12\" [-password-length N]\n")
	fmt.Fprintf(w, "  gopassgen -mnemonic-stdin [-password-length N]\n")
	fmt.Fprintf(w, "  gopassgen -mnemonic-only [-count N] [-words N] [-output FILE]\n")
	fmt.Fprintf(w, "  gopassgen -auto-gen [-phrases N] [-words N] [-password-length N] [-output FILE]\n")
	fmt.Fprintf(w, "  gopassgen -self-test | -version\n\nOptions:\n")
	fs.PrintDefaults()
	fmt.Fprintf(w, "\nExit codes:\n  0 success   1 error   2 usage   130 interrupted\n")
	fmt.Fprintf(w, "\nSecurity:\n")
	fmt.Fprintf(w, "  -mnemonic puts the phrase in your shell history and in ps output.\n")
	fmt.Fprintf(w, "  Prefer -mnemonic-stdin for anything you actually use.\n")
}

func run(ctx context.Context, opts *options, stdin io.Reader, stdout io.Writer, log *slog.Logger) error {
	switch {
	case opts.showVersion:
		fmt.Fprintln(stdout, buildinfo.VersionString())
		return nil
	case opts.selfTest:
		return runSelfTest(stdout, log)
	}

	if err := validateModes(opts); err != nil {
		return err
	}

	// The language applies to the whole run, so it is attached once here and
	// inherited by every record, including those from package passgen.
	log = log.With(slog.String("language", opts.language))
	log.Debug("starting",
		slog.String("version", buildinfo.Version),
		slog.String("derivation", buildinfo.DerivationVersion),
	)

	gen, err := passgen.New(opts.language, log)
	if err != nil {
		return err
	}

	switch {
	case opts.mnemonic != "" || opts.mnemonicStdin:
		return runSingle(opts, gen, stdin, stdout, log)
	case opts.mnemonicOnly:
		return runMnemonicOnly(ctx, opts, gen, stdout, log)
	case opts.autoGen:
		return runAutoGen(ctx, opts, gen, stdout, log)
	default:
		return usagef("no mode selected: use -mnemonic, -mnemonic-stdin, -mnemonic-only or -auto-gen")
	}
}

// validateModes rejects contradictory or out-of-range combinations before any
// work starts, so the tool never half-produces output and then fails.
func validateModes(opts *options) error {
	hasMnemonic := opts.mnemonic != "" || opts.mnemonicStdin

	if opts.mnemonic != "" && opts.mnemonicStdin {
		return usagef("cannot use -mnemonic together with -mnemonic-stdin")
	}
	if hasMnemonic && (opts.autoGen || opts.mnemonicOnly) {
		return usagef("cannot use -mnemonic/-mnemonic-stdin together with -auto-gen/-mnemonic-only")
	}
	if opts.autoGen && opts.mnemonicOnly {
		return usagef("cannot use -auto-gen and -mnemonic-only together")
	}
	if !bip39.IsSupported(opts.language) {
		return usagef("unsupported language %q (supported: %s)",
			opts.language, strings.Join(bip39.Languages(), ", "))
	}
	if _, ok := bip39.StrengthBits(opts.words); !ok {
		return usagef("invalid -words %d (want one of %v)", opts.words, bip39.WordCounts())
	}
	if opts.jobs < 0 {
		return usagef("-jobs must be >= 0, got %d", opts.jobs)
	}

	// Password length only matters when a password is produced.
	if !opts.mnemonicOnly {
		if opts.passwordLength <= 0 {
			return usagef("-password-length must be positive, got %d", opts.passwordLength)
		}
		if opts.passwordLength > derive.MaxPasswordLength {
			return usagef("-password-length %d exceeds maximum %d",
				opts.passwordLength, derive.MaxPasswordLength)
		}
	}

	if opts.autoGen {
		if opts.phrases <= 0 {
			return usagef("-phrases must be positive, got %d", opts.phrases)
		}
		if opts.phrases > maxNumPhrases {
			return usagef("-phrases %d exceeds maximum %d", opts.phrases, maxNumPhrases)
		}
	}

	if opts.mnemonicOnly {
		count := effectiveCount(opts)
		if count <= 0 {
			return usagef("-count must be positive, got %d", count)
		}
		if count > maxMnemonicOnlyCount {
			return usagef("-count %d exceeds maximum %d", count, maxMnemonicOnlyCount)
		}
		if count > bigCountRequiresOutput && opts.output == "" {
			return usagef("-output is required for -count above %d", bigCountRequiresOutput)
		}
	}
	return nil
}

// effectiveCount reproduces the Python fallback for -mnemonic-only:
// an explicit -count wins, otherwise -phrases is used, otherwise 1.
//
// It keys off whether the flag was passed, not off its value, so an explicit
// "-count 0" reaches the "must be positive" error instead of silently
// becoming 1 — same as the Python original, where args.count is None only
// when the flag is absent.
func effectiveCount(opts *options) int {
	if opts.wasSet("count") {
		return opts.count
	}
	if opts.wasSet("phrases") {
		return opts.phrases
	}
	return 1
}

func runSingle(opts *options, gen *passgen.Generator, stdin io.Reader, stdout io.Writer, log *slog.Logger) error {
	mnemonic := opts.mnemonic
	if opts.mnemonicStdin {
		var err error
		mnemonic, err = readMnemonic(stdin)
		if err != nil {
			return err
		}
	} else {
		log.Warn("-mnemonic exposes the phrase in shell history and ps; prefer -mnemonic-stdin")
	}

	log.Info("deriving password", slog.Int("length", opts.passwordLength))

	pw, err := gen.Password(mnemonic, opts.passwordLength)
	if err != nil {
		return err
	}
	defer derive.Wipe(pw)

	w := bufio.NewWriter(stdout)
	if _, err := w.Write(pw); err != nil {
		return fmt.Errorf("writing password: %w", err)
	}
	if err := w.WriteByte('\n'); err != nil {
		return fmt.Errorf("writing password: %w", err)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("writing password: %w", err)
	}
	log.Info("done")
	return nil
}

// readMnemonic reads a phrase from r, stripping exactly one trailing newline.
//
// No other whitespace is touched: the reference implementation hashes the
// phrase verbatim, so trimming spaces here would change the derived password.
func readMnemonic(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, 64*1024))
	if err != nil {
		return "", fmt.Errorf("reading mnemonic from stdin: %w", err)
	}
	s := string(data)
	s = strings.TrimSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\r")
	if s == "" {
		return "", errors.New("no mnemonic on stdin")
	}
	return s, nil
}

func runMnemonicOnly(ctx context.Context, opts *options, gen *passgen.Generator, stdout io.Writer, log *slog.Logger) error {
	count := effectiveCount(opts)
	log.Info("generating mnemonics",
		slog.Int("count", count),
		slog.Int("words", opts.words),
	)

	sink, closeSink, err := openSink(opts.output, stdout)
	if err != nil {
		return err
	}
	defer closeSink()

	for i := 0; i < count; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		m, err := gen.Mnemonic(opts.words)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(sink, m); err != nil {
			return fmt.Errorf("writing mnemonic: %w", err)
		}
	}
	if opts.output != "" {
		log.Info("wrote mnemonics",
			slog.Int("count", count),
			slog.String("path", opts.output),
		)
	}
	return nil
}

func runAutoGen(ctx context.Context, opts *options, gen *passgen.Generator, stdout io.Writer, log *slog.Logger) error {
	log.Info("generating pairs",
		slog.Int("pairs", opts.phrases),
		slog.Int("words", opts.words),
		slog.Int("length", opts.passwordLength),
	)

	pairs, err := gen.Pairs(ctx, opts.phrases, opts.words, opts.passwordLength, opts.jobs)
	if err != nil {
		return err
	}
	defer func() {
		for i := range pairs {
			pairs[i].Wipe()
		}
	}()

	var (
		file      io.Writer
		closeFile = func() {}
	)
	if opts.output != "" {
		f, closer, err := openSink(opts.output, nil)
		if err != nil {
			return err
		}
		file, closeFile = f, closer
	}
	defer closeFile()

	out := bufio.NewWriter(stdout)
	for i, p := range pairs {
		if _, err := fmt.Fprintf(out, "Mnemonic %d: %s\nPassword %d: %s\n\n",
			i+1, p.Mnemonic, i+1, p.Password); err != nil {
			return fmt.Errorf("writing pair: %w", err)
		}
		if file != nil {
			if _, err := fmt.Fprintf(file, "%s\n%s\n", p.Mnemonic, p.Password); err != nil {
				return fmt.Errorf("writing pair to %s: %w", opts.output, err)
			}
		}
	}
	if err := out.Flush(); err != nil {
		return fmt.Errorf("writing pairs: %w", err)
	}
	if opts.output != "" {
		log.Info("wrote pairs",
			slog.Int("pairs", len(pairs)),
			slog.String("path", opts.output),
		)
	}
	return nil
}

// openSink returns a buffered writer for path, or for fallback when path is
// empty. The returned close function flushes and, for files, closes and
// reports nothing — flush errors are surfaced by the caller's writes where
// possible, so the close function is deliberately side-effect free on error
// paths that already failed.
func openSink(path string, fallback io.Writer) (io.Writer, func(), error) {
	if path == "" {
		if fallback == nil {
			return io.Discard, func() {}, nil
		}
		w := bufio.NewWriter(fallback)
		return w, func() { _ = w.Flush() }, nil
	}

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, nil, fmt.Errorf("creating directory for %s: %w", path, err)
		}
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, outputFileMode)
	if err != nil {
		return nil, nil, fmt.Errorf("opening %s: %w", path, err)
	}
	w := bufio.NewWriterSize(f, 1<<20)
	return w, func() {
		_ = w.Flush()
		_ = f.Sync()
		_ = f.Close()
	}, nil
}

func runSelfTest(stdout io.Writer, log *slog.Logger) error {
	log.Info("self-test",
		slog.String("version", buildinfo.Version),
		slog.String("derivation", buildinfo.DerivationVersion),
		slog.String("platform", runtime.GOOS+"/"+runtime.GOARCH),
	)

	results, err := passgen.SelfTest()
	for _, r := range results {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		}
		fmt.Fprintf(stdout, "%-4s %-12s %s\n", status, r.Name, r.Detail)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "\nall %d checks passed\n", len(results))
	return nil
}
