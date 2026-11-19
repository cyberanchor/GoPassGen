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
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/cyberanchor/GoPassGen/internal/bip39"
	"github.com/cyberanchor/GoPassGen/internal/buildinfo"
	"github.com/cyberanchor/GoPassGen/internal/derive"
	"github.com/cyberanchor/GoPassGen/internal/logx"
	"github.com/cyberanchor/GoPassGen/internal/passgen"
	"github.com/cyberanchor/GoPassGen/internal/term"
)

// Exit codes.
const (
	// ExitOK signals success.
	ExitOK = 0
	// ExitError signals a runtime failure (invalid mnemonic, I/O error, ...).
	ExitError = 1
	// ExitUsage signals a malformed or contradictory command line.
	ExitUsage = 2
	// ExitInterrupted signals SIGINT/SIGTERM.
	ExitInterrupted = 130
)

// Limits mirroring pypassgen.py.
const (
	maxNumPhrases          = 100
	maxMnemonicOnlyCount   = 10_000
	bigCountRequiresOutput = 1_000
)

// maxMnemonicInput bounds what -mnemonic-stdin reads, so a hostile or accidental
// stream cannot exhaust memory. A real phrase is far smaller.
const maxMnemonicInput = 64 * 1024

// hiddenValue replaces user-supplied text in diagnostics under -case-sensitive.
const hiddenValue = "<hidden>"

// runSelfTests is replaced by a test: an intact binary never fails its self-test.
var runSelfTests = passgen.SelfTestContext

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
	caseSensitive  bool
	selfTest       bool
	showVersion    bool

	// set records which flags the user passed explicitly. It reproduces the
	// Python "is None" checks: -count 0 must be an error, not a fallback.
	set map[string]bool
}

func (o *options) wasSet(name string) bool { return o.set[name] }

// quoted renders a user-supplied value for a diagnostic. Such a value may be a
// mnemonic pasted into the wrong place, so -case-sensitive hides it.
func (o *options) quoted(value string) string {
	if o.caseSensitive {
		return hiddenValue
	}
	return strconv.Quote(value)
}

// pathAttr is the log attribute for the -output path.
func (o *options) pathAttr() slog.Attr {
	if o.caseSensitive {
		return slog.String("path", hiddenValue)
	}
	return slog.String("path", o.output)
}

// usageError marks a command line problem, which exits with ExitUsage.
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func usagef(format string, args ...any) error {
	return usageError{fmt.Errorf(format, args...)}
}

// decimalFlag is an integer flag that accepts only plain decimal digits.
//
// flag.IntVar also understands base prefixes, so "016" silently meant 14 and
// "-count 010" produced 8 lines, while PyPassGen reads them as 16 and 10. Signs
// are refused here too: no option has a meaningful negative value, and this way
// one is rejected in every mode, including those that do not use the option.
type decimalFlag struct{ target *int }

func (d decimalFlag) String() string {
	if d.target == nil {
		return "0"
	}
	return strconv.Itoa(*d.target)
}

func (d decimalFlag) Set(s string) error {
	digits := strings.TrimPrefix(s, "-")
	switch {
	case digits == "" || strings.Trim(digits, "0123456789") != "":
		return errors.New("must be a decimal integer")
	case digits != s:
		return errors.New("negative values are not allowed")
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return errors.New("value is too large")
	}
	*d.target = n
	return nil
}

// Run executes the CLI and returns a process exit code.
//
// The first SIGINT or SIGTERM cancels the run so it can clean up and exit with
// ExitInterrupted. After that the default handling is restored, so a second
// signal ends the process at once even if an operation is stuck.
func Run(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	context.AfterFunc(ctx, stop)
	return RunContext(ctx, args, os.Stdin, stdout, stderr)
}

// RunContext is Run with caller-supplied context and stdin. Tests use it to
// exercise every path without touching process state.
func RunContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, fs, err := parse(args)
	if errors.Is(err, flag.ErrHelp) {
		printUsage(stderr, fs)
		return ExitOK
	}

	// The logger comes first: even a bad command line is reported in the level
	// and format the user asked for.
	log, format, logErr := newLogger(opts, stderr)
	if err == nil {
		err = logErr
	}
	if err == nil {
		err = run(ctx, opts, stdin, stdout, log)
	}

	var (
		ue usageError
		oe *outputError
	)
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		log.Warn("interrupted")
		return ExitInterrupted
	case errors.As(err, &ue):
		log.Error("invalid usage", slog.String("error", err.Error()))
		if format == logx.FormatPretty && log.Enabled(ctx, slog.LevelError) {
			fmt.Fprintln(stderr)
			printUsage(stderr, fs)
		}
		return ExitUsage
	case errors.As(err, &oe):
		log.Error("failed", slog.String("error", err.Error()), opts.pathAttr())
		return ExitError
	default:
		log.Error("failed", slog.String("error", err.Error()))
		return ExitError
	}
}

// newLogger builds the logger from the parsed options. It always returns a
// usable logger, falling back to the defaults for an invalid setting, so that
// the invalid setting itself can be reported.
func newLogger(opts *options, stderr io.Writer) (*slog.Logger, logx.Format, error) {
	var firstErr error
	fail := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}

	level := slog.LevelInfo
	if opts.logLevel != "" {
		parsed, err := logx.ParseLevel(opts.logLevel)
		switch {
		case err == nil:
			level = parsed
		case opts.caseSensitive:
			fail(usagef("unknown log level %s (want: silent, error, warn, info, debug)", hiddenValue))
		default:
			fail(usageError{err})
		}
	}
	if opts.verbose {
		if firstErr == nil && opts.wasSet("log-level") && level != slog.LevelDebug {
			fail(usagef("-v/-verbose contradicts -log-level %s", opts.quoted(opts.logLevel)))
		}
		level = slog.LevelDebug
	}

	format, err := logx.ParseFormat(opts.logFormat)
	if err != nil {
		if opts.caseSensitive {
			err = fmt.Errorf("unknown log format %s (want: pretty, json)", hiddenValue)
		}
		fail(usageError{err})
	}

	log := logx.New(stderr, logx.Options{
		Level:  level,
		Format: format,
		Color:  logx.ColorEnabled(stderr, opts.noColor),
	})
	return log, format, firstErr
}

func parse(args []string) (*options, *flag.FlagSet, error) {
	opts := &options{
		phrases:        1,
		words:          12,
		passwordLength: derive.DefaultPasswordLength,
	}
	fs := flag.NewFlagSet("gopassgen", flag.ContinueOnError)
	// All reporting happens in RunContext, once and in the selected log format.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	fs.StringVar(&opts.mnemonic, "mnemonic", "", "BIP-39 mnemonic phrase to derive a password from")
	fs.BoolVar(&opts.mnemonicStdin, "mnemonic-stdin", false, "read the mnemonic from stdin (keeps it out of shell history and ps)")
	fs.BoolVar(&opts.autoGen, "auto-gen", false, "generate mnemonic+password pairs")
	fs.BoolVar(&opts.mnemonicOnly, "mnemonic-only", false, "generate mnemonics only, no passwords")
	fs.Var(decimalFlag{&opts.count}, "count", fmt.Sprintf("generate `N` mnemonics with -mnemonic-only (default 1, max %d)", maxMnemonicOnlyCount))
	fs.Var(decimalFlag{&opts.phrases}, "phrases", fmt.Sprintf("generate `N` pairs with -auto-gen (max %d)", maxNumPhrases))
	fs.Var(decimalFlag{&opts.words}, "words", fmt.Sprintf("`N` words per generated phrase %v", bip39.WordCounts()))
	fs.Var(decimalFlag{&opts.passwordLength}, "password-length", fmt.Sprintf("password length `N` (max %d)", derive.MaxPasswordLength))
	fs.StringVar(&opts.language, "language", "english", "wordlist language "+strings.Join(bip39.Languages(), "|"))
	fs.StringVar(&opts.output, "output", "", "write results to this file instead of stdout; an existing file is replaced after a warning")
	fs.Var(decimalFlag{&opts.jobs}, "jobs", "run `N` derivations in parallel with -auto-gen (default: number of CPUs)")
	fs.BoolVar(&opts.verbose, "v", false, "shorthand for -log-level debug")
	fs.BoolVar(&opts.verbose, "verbose", false, "shorthand for -log-level debug")
	fs.StringVar(&opts.logLevel, "log-level", "", "silent|error|warn|info|debug (default info)")
	fs.StringVar(&opts.logFormat, "log-format", "", "pretty|json (default pretty)")
	fs.BoolVar(&opts.noColor, "no-color", false, "disable ANSI colour in logs")
	fs.BoolVar(&opts.caseSensitive, "case-sensitive", false, "treat this case as sensitive: hide phrases, file names and other values you typed from logs and errors")
	fs.BoolVar(&opts.selfTest, "self-test", false, "run built-in known-answer tests and exit")
	fs.BoolVar(&opts.showVersion, "version", false, "print version and exit")

	positional, err := parseAll(fs, args)

	opts.set = make(map[string]bool, fs.NFlag())
	fs.Visit(func(f *flag.Flag) { opts.set[f.Name] = true })
	// Decided from the raw arguments: the flag must also protect a value that
	// comes before it, or one the parser never reaches.
	opts.caseSensitive = wantsHiddenValues(args)

	switch {
	case errors.Is(err, flag.ErrHelp):
		return opts, fs, err
	case err != nil && opts.caseSensitive:
		return opts, fs, usageError{hideFlagError(fs, err)}
	case err != nil:
		return opts, fs, usageError{err}
	case len(positional) > 0:
		return opts, fs, usagef("unexpected positional argument %s (did you forget to quote the mnemonic?)",
			opts.quoted(positional[0]))
	}
	return opts, fs, nil
}

// parseAll keeps parsing after an error or a positional argument and returns
// the first error. The flag package stops at either one, which would leave
// -log-format, -log-level and -case-sensitive unseen exactly when an error has
// to be reported.
func parseAll(fs *flag.FlagSet, args []string) (positional []string, first error) {
	rest := args
	for {
		err := fs.Parse(rest)
		next := fs.Args()
		if err != nil && first == nil {
			first = err
		}
		if len(next) == 0 {
			return positional, first
		}
		if err == nil {
			positional = append(positional, next[0])
		}
		if err == nil || len(next) == len(rest) {
			next = next[1:] // always make progress
		}
		rest = next
	}
}

// wantsHiddenValues reports whether -case-sensitive is in effect. A mention that
// the parser would read as another flag's value still counts: hiding too much
// is harmless, printing a phrase is not.
func wantsHiddenValues(args []string) bool {
	hide := false
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if name != "case-sensitive" {
			continue
		}
		hide = true
		if hasValue {
			if v, err := strconv.ParseBool(value); err == nil {
				hide = v
			}
		}
	}
	return hide
}

// hideFlagError rewrites a flag package error so it contains no user input.
// Anything unrecognised becomes a generic message, so a change in the wording
// of the flag package can cost detail but can never leak a value.
func hideFlagError(fs *flag.FlagSet, err error) error {
	msg := err.Error()
	if strings.HasPrefix(msg, "flag needs an argument: ") {
		return err // it names a defined flag and nothing else
	}
	if i := strings.LastIndex(msg, " for "); strings.HasPrefix(msg, "invalid ") && i >= 0 {
		name, reason, ok := strings.Cut(strings.TrimPrefix(msg[i+len(" for "):], "flag "), ": ")
		name = strings.TrimPrefix(name, "-")
		if ok && fs.Lookup(name) != nil {
			return fmt.Errorf("invalid value %s for -%s: %s", hiddenValue, name, reason)
		}
	}
	return fmt.Errorf("unknown or malformed flag %s", hiddenValue)
}

func printUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(w, "%s  v%s\n\n", banner, buildinfo.Version)
	fmt.Fprintf(w, "Deterministic passwords from BIP-39 mnemonic phrases.\n")
	fmt.Fprintf(w, "Bit-compatible with PyPassGen %s.\n\n", strings.TrimPrefix(buildinfo.DerivationVersion, "pypassgen-"))
	fmt.Fprintf(w, "Usage:\n  gopassgen -mnemonic \"word1 ... word12\" [-password-length N] [-output FILE]\n")
	fmt.Fprintf(w, "  gopassgen -mnemonic-stdin [-password-length N] [-output FILE]\n")
	fmt.Fprintf(w, "  gopassgen -mnemonic-only [-count N] [-words N] [-output FILE]\n")
	fmt.Fprintf(w, "  gopassgen -auto-gen [-phrases N] [-words N] [-password-length N] [-jobs N] [-output FILE]\n")
	fmt.Fprintf(w, "  gopassgen -self-test | -version\n\nOptions:\n")
	fs.SetOutput(w)
	fs.PrintDefaults()
	fs.SetOutput(io.Discard)
	fmt.Fprintf(w, "\nExit codes:\n  0 success   1 error   2 usage   130 interrupted\n")
	fmt.Fprintf(w, "\nSecurity:\n")
	fmt.Fprintf(w, "  -mnemonic puts the phrase in your shell history and in ps output.\n")
	fmt.Fprintf(w, "  Prefer -mnemonic-stdin for anything you actually use.\n")
	fmt.Fprintf(w, "  -output files get ordinary permissions (0644 minus your umask).\n")
}

func run(ctx context.Context, opts *options, stdin io.Reader, stdout io.Writer, log *slog.Logger) error {
	if err := validateModes(opts); err != nil {
		return err
	}

	stdout = contextWriter{ctx: ctx, w: stdout}
	switch {
	case opts.showVersion:
		return writeText(stdout, buildinfo.VersionString()+"\n")
	case opts.selfTest:
		return runSelfTest(ctx, stdout, log)
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
	case opts.mnemonicOnly:
		return runMnemonicOnly(ctx, opts, gen, stdout, log)
	case opts.autoGen:
		return runAutoGen(ctx, opts, gen, stdout, log)
	default:
		return runSingle(ctx, opts, gen, stdin, stdout, log)
	}
}

// validateModes rejects contradictory, meaningless or out-of-range combinations
// before any work starts, so the tool never half-produces output and then fails,
// and never silently ignores something the user asked for.
func validateModes(opts *options) error {
	if opts.showVersion || opts.selfTest {
		return validateInfoMode(opts)
	}

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
	if !hasMnemonic && !opts.autoGen && !opts.mnemonicOnly {
		return usagef("no mode selected: use -mnemonic, -mnemonic-stdin, -mnemonic-only or -auto-gen")
	}
	if !bip39.IsSupported(opts.language) {
		return usagef("unsupported language %s (supported: %s)",
			opts.quoted(opts.language), strings.Join(bip39.Languages(), ", "))
	}
	if opts.wasSet("output") && opts.output == "" {
		return usagef("-output needs a file name")
	}

	generates := opts.autoGen || opts.mnemonicOnly
	for _, rule := range []struct {
		flag    string
		applies bool
		modes   string
	}{
		{"count", opts.mnemonicOnly, "-mnemonic-only"},
		{"phrases", generates, "-auto-gen and -mnemonic-only"},
		{"words", generates, "-auto-gen and -mnemonic-only"},
		{"password-length", !opts.mnemonicOnly, "-mnemonic, -mnemonic-stdin and -auto-gen"},
		{"jobs", opts.autoGen, "-auto-gen"},
	} {
		if opts.wasSet(rule.flag) && !rule.applies {
			return usagef("-%s applies only to %s", rule.flag, rule.modes)
		}
	}

	if _, ok := bip39.StrengthBits(opts.words); !ok {
		return usagef("invalid -words %d (want one of %v)", opts.words, bip39.WordCounts())
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

// validateInfoMode checks -version and -self-test, which take no work options.
// The logging flags stay allowed.
func validateInfoMode(opts *options) error {
	if opts.showVersion && opts.selfTest {
		return usagef("cannot use -version and -self-test together")
	}
	mode := "-version"
	if opts.selfTest {
		mode = "-self-test"
	}
	for _, name := range []string{
		"mnemonic", "mnemonic-stdin", "auto-gen", "mnemonic-only", "count", "phrases",
		"words", "password-length", "language", "output", "jobs",
	} {
		if opts.wasSet(name) {
			return usagef("cannot use %s together with -%s", mode, name)
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

func runSingle(ctx context.Context, opts *options, gen *passgen.Generator, stdin io.Reader, stdout io.Writer, log *slog.Logger) error {
	// The destination is checked first, so a bad -output is reported before the
	// user types a phrase and before the expensive derivation.
	out, err := openSink(ctx, opts, stdout, log)
	if err != nil {
		return err
	}
	defer out.abort()

	mnemonic := opts.mnemonic
	if opts.mnemonicStdin {
		mnemonic, err = readMnemonicInput(ctx, stdin, log)
		if err != nil {
			return err
		}
	} else {
		log.Warn("-mnemonic exposes the phrase in shell history and ps; prefer -mnemonic-stdin")
	}

	log.Info("deriving password", slog.Int("length", opts.passwordLength))

	pw, err := gen.PasswordContext(ctx, mnemonic, opts.passwordLength)
	if err != nil {
		return err
	}
	defer derive.Wipe(pw)

	out.write(pw)
	out.writeString("\n")
	if err := out.commit(); err != nil {
		return err
	}
	if opts.output != "" {
		log.Info("wrote password", opts.pathAttr())
	}
	log.Info("done")
	return nil
}

// readMnemonicInput reads the phrase from stdin and gives up when ctx is
// cancelled. The read itself cannot be interrupted, so it runs in a goroutine
// that is abandoned on cancellation; the process is about to exit anyway.
func readMnemonicInput(ctx context.Context, stdin io.Reader, log *slog.Logger) (string, error) {
	read := readMnemonic
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(f.Fd()) {
		// On a terminal one line is the whole input: waiting for end-of-file
		// would leave Enter apparently doing nothing.
		read = readMnemonicLine
		restore, err := term.DisableEcho(f.Fd())
		if err != nil {
			log.Warn("cannot hide terminal input, the phrase will be visible", slog.String("error", err.Error()))
		} else {
			defer func() { _ = restore() }()
		}
		log.Info("type the mnemonic and press Enter")
	}

	type result struct {
		mnemonic string
		err      error
	}
	done := make(chan result, 1)
	go func() {
		m, err := read(stdin)
		done <- result{m, err}
	}()
	select {
	case r := <-done:
		return r.mnemonic, r.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// readMnemonic reads a phrase from r, stripping exactly one trailing newline.
//
// No other whitespace is touched: the reference implementation hashes the
// phrase verbatim, so trimming spaces here would change the derived password.
func readMnemonic(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxMnemonicInput))
	if err != nil {
		return "", fmt.Errorf("reading mnemonic from stdin: %w", err)
	}
	return trimMnemonicInput(string(data))
}

// readMnemonicLine reads a phrase that ends at the first newline.
func readMnemonicLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(r, maxMnemonicInput)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("reading mnemonic from stdin: %w", err)
	}
	return trimMnemonicInput(line)
}

func trimMnemonicInput(s string) (string, error) {
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

	out, err := openSink(ctx, opts, stdout, log)
	if err != nil {
		return err
	}
	defer out.abort()

	for i := 0; i < count; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		m, err := gen.Mnemonic(opts.words)
		if err != nil {
			return err
		}
		out.writeString(m)
		out.writeString("\n")
		if out.err != nil {
			return out.err
		}
	}
	if err := out.commit(); err != nil {
		return err
	}
	if opts.output != "" {
		log.Info("wrote mnemonics",
			slog.Int("count", count),
			opts.pathAttr(),
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

	// Opened before the derivations: finding out afterwards that the file cannot
	// be written would throw all of that work away.
	out, err := openSink(ctx, opts, stdout, log)
	if err != nil {
		return err
	}
	defer out.abort()

	pairs, err := gen.Pairs(ctx, opts.phrases, opts.words, opts.passwordLength, opts.jobs)
	if err != nil {
		return err
	}
	defer func() {
		for i := range pairs {
			pairs[i].Wipe()
		}
	}()

	for i, p := range pairs {
		if opts.output != "" {
			out.writeString(p.Mnemonic)
			out.writeString("\n")
			out.write(p.Password)
			out.writeString("\n")
			continue
		}
		n := strconv.Itoa(i + 1)
		out.writeString("Mnemonic " + n + ": ")
		out.writeString(p.Mnemonic)
		out.writeString("\nPassword " + n + ": ")
		out.write(p.Password)
		out.writeString("\n\n")
	}
	if err := out.commit(); err != nil {
		return err
	}
	if opts.output != "" {
		log.Info("wrote pairs",
			slog.Int("pairs", len(pairs)),
			opts.pathAttr(),
		)
	}
	return nil
}

func runSelfTest(ctx context.Context, stdout io.Writer, log *slog.Logger) error {
	log.Info("self-test",
		slog.String("version", buildinfo.Version),
		slog.String("derivation", buildinfo.DerivationVersion),
		slog.String("platform", runtime.GOOS+"/"+runtime.GOARCH),
	)

	results, testErr := runSelfTests(ctx)

	var report strings.Builder
	for _, r := range results {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		}
		fmt.Fprintf(&report, "%-4s %-12s %s\n", status, r.Name, r.Detail)
	}
	if testErr == nil {
		fmt.Fprintf(&report, "\nall %d checks passed\n", len(results))
	}
	if err := writeText(stdout, report.String()); err != nil {
		return err
	}
	return testErr
}
