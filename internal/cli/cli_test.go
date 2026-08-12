package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopassgen/internal/bip39"
	"gopassgen/internal/buildinfo"
	"gopassgen/internal/derive"
)

const (
	validEN = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	// Reference outputs of PyPassGen 1.3.5.
	validENPassword12 = ",6UiYsb-haPx"
	validENPassword16 = ",6UiYsb-haPxbRcv"
)

type result struct {
	code   int
	stdout string
	stderr string
}

// exec runs the CLI with no stdin and a background context.
func exec(t *testing.T, args ...string) result {
	t.Helper()
	return execStdin(t, "", args...)
}

func execStdin(t *testing.T, stdin string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	code := RunContext(context.Background(), args, strings.NewReader(stdin), &out, &errb)
	return result{code: code, stdout: out.String(), stderr: errb.String()}
}

// ---------------------------------------------------------------------------
// Informational modes
// ---------------------------------------------------------------------------

func TestVersion(t *testing.T) {
	r := exec(t, "-version")
	if r.code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	for _, want := range []string{buildinfo.Name, buildinfo.Version, buildinfo.DerivationVersion, runtime.GOOS} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("version output missing %q:\n%s", want, r.stdout)
		}
	}
}

func TestHelp(t *testing.T) {
	for _, flag := range []string{"-h", "-help", "--help"} {
		r := exec(t, flag)
		if r.code != ExitOK {
			t.Errorf("%s: exit = %d, want %d", flag, r.code, ExitOK)
		}
		if !strings.Contains(r.stderr, "Usage:") {
			t.Errorf("%s: usage text missing from stderr", flag)
		}
		if r.stdout != "" {
			t.Errorf("%s: help must not pollute stdout: %q", flag, r.stdout)
		}
	}
}

func TestHelpListsEveryLanguageAndWordCount(t *testing.T) {
	r := exec(t, "-h")
	for _, lang := range bip39.Languages() {
		if !strings.Contains(r.stderr, lang) {
			t.Errorf("help does not mention language %q", lang)
		}
	}
	if !strings.Contains(r.stderr, "-mnemonic-stdin") {
		t.Error("help must document -mnemonic-stdin")
	}
}

func TestNoArgumentsShowsUsage(t *testing.T) {
	r := exec(t)
	if r.code != ExitUsage {
		t.Errorf("exit = %d, want %d", r.code, ExitUsage)
	}
	if !strings.Contains(r.stderr, "no mode selected") {
		t.Errorf("stderr = %q", r.stderr)
	}
}

func TestSelfTest(t *testing.T) {
	if testing.Short() {
		t.Skip("1,000,000 PBKDF2 iterations")
	}
	r := exec(t, "-self-test")
	if r.code != ExitOK {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
	if strings.Contains(r.stdout, "FAIL") {
		t.Errorf("a check failed:\n%s", r.stdout)
	}
	for _, name := range []string{"alphabet", "wordlists", "nfkd", "bip39-seed", "stream", "kdf", "end-to-end"} {
		if !strings.Contains(r.stdout, name) {
			t.Errorf("self-test output missing %q", name)
		}
	}
	if !strings.Contains(r.stdout, "all 7 checks passed") {
		t.Errorf("summary line missing:\n%s", r.stdout)
	}
}

// ---------------------------------------------------------------------------
// Password mode
// ---------------------------------------------------------------------------

func TestMnemonicMode(t *testing.T) {
	if testing.Short() {
		t.Skip("1,000,000 PBKDF2 iterations")
	}
	r := exec(t, "-mnemonic", validEN, "-password-length", "16")
	if r.code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	if got := strings.TrimRight(r.stdout, "\n"); got != validENPassword16 {
		t.Errorf("stdout = %q, want %q", got, validENPassword16)
	}
	if strings.Contains(r.stdout, "Generated") {
		t.Error("stdout must contain the password only, so it can be piped")
	}
	if !strings.Contains(r.stderr, "shell history") {
		t.Error("expected a warning about -mnemonic exposing the phrase")
	}
}

func TestMnemonicDefaultLength(t *testing.T) {
	if testing.Short() {
		t.Skip("1,000,000 PBKDF2 iterations")
	}
	r := exec(t, "-mnemonic", validEN)
	if r.code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	got := strings.TrimRight(r.stdout, "\n")
	if len(got) != derive.DefaultPasswordLength {
		t.Errorf("default length = %d, want %d", len(got), derive.DefaultPasswordLength)
	}
	if got != validENPassword12 {
		t.Errorf("stdout = %q, want %q", got, validENPassword12)
	}
}

func TestMnemonicStdin(t *testing.T) {
	if testing.Short() {
		t.Skip("1,000,000 PBKDF2 iterations")
	}
	// A trailing newline must be stripped, and nothing else.
	for _, input := range []string{validEN, validEN + "\n", validEN + "\r\n"} {
		r := execStdin(t, input, "-mnemonic-stdin", "-password-length", "16")
		if r.code != ExitOK {
			t.Fatalf("input %q: exit = %d, stderr = %s", input, r.code, r.stderr)
		}
		if got := strings.TrimRight(r.stdout, "\n"); got != validENPassword16 {
			t.Errorf("input %q: stdout = %q, want %q", input, got, validENPassword16)
		}
		if strings.Contains(r.stderr, "shell history") {
			t.Error("-mnemonic-stdin must not warn about shell history")
		}
	}
}

func TestMnemonicStdinEmpty(t *testing.T) {
	r := execStdin(t, "", "-mnemonic-stdin")
	if r.code != ExitError {
		t.Errorf("exit = %d, want %d", r.code, ExitError)
	}
	if !strings.Contains(r.stderr, "no mnemonic") {
		t.Errorf("stderr = %q", r.stderr)
	}
}

func TestMnemonicStdinPreservesInnerWhitespace(t *testing.T) {
	// A double space must still be rejected: the reference implementation
	// hashes the phrase verbatim, so silently repairing it would produce a
	// different password.
	r := execStdin(t, strings.Replace(validEN, "abandon abandon", "abandon  abandon", 1)+"\n", "-mnemonic-stdin")
	if r.code != ExitError {
		t.Errorf("exit = %d, want %d", r.code, ExitError)
	}
	if !strings.Contains(r.stderr, "invalid mnemonic") {
		t.Errorf("stderr = %q", r.stderr)
	}
}

func TestInvalidMnemonicIsRejected(t *testing.T) {
	cases := []struct {
		name     string
		mnemonic string
		want     string
	}{
		{"bad checksum", strings.Replace(validEN, "about", "abandon", 1), "checksum"},
		{"unknown word", strings.Replace(validEN, "about", "zzzz", 1), "wordlist"},
		{"too few words", "abandon abandon abandon", "word count"},
		{"wrong language", "cligner gouffre monotone mutuel sortir rythme decider mignon febrile refuge magique incolore", "wordlist"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := exec(t, "-mnemonic", c.mnemonic)
			if r.code != ExitError {
				t.Fatalf("exit = %d, want %d", r.code, ExitError)
			}
			if !strings.Contains(r.stderr, c.want) {
				t.Errorf("stderr = %q, want it to mention %q", r.stderr, c.want)
			}
			if r.stdout != "" {
				t.Errorf("nothing must reach stdout on failure, got %q", r.stdout)
			}
		})
	}
}

func TestErrorsDoNotEchoTheMnemonic(t *testing.T) {
	secret := strings.Replace(validEN, "about", "hunter2word", 1)
	r := exec(t, "-mnemonic", secret)
	if r.code != ExitError {
		t.Fatalf("exit = %d", r.code)
	}
	for _, word := range strings.Fields(secret) {
		if strings.Contains(r.stderr, word) {
			t.Fatalf("stderr leaked mnemonic word %q:\n%s", word, r.stderr)
		}
	}
}

// ---------------------------------------------------------------------------
// Mnemonic-only mode
// ---------------------------------------------------------------------------

func TestMnemonicOnlyDefaults(t *testing.T) {
	r := exec(t, "-mnemonic-only")
	if r.code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	lines := strings.Split(strings.TrimRight(r.stdout, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	if got := bip39.WordCount(lines[0]); got != 12 {
		t.Errorf("default word count = %d, want 12", got)
	}
}

func TestMnemonicOnlyCountAndWords(t *testing.T) {
	for _, words := range bip39.WordCounts() {
		r := exec(t, "-mnemonic-only", "-count", "5", "-words", itoa(words))
		if r.code != ExitOK {
			t.Fatalf("words=%d: exit = %d, stderr = %s", words, r.code, r.stderr)
		}
		lines := strings.Split(strings.TrimRight(r.stdout, "\n"), "\n")
		if len(lines) != 5 {
			t.Fatalf("words=%d: got %d lines, want 5", words, len(lines))
		}
		wl, err := bip39.Load("english")
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range lines {
			if bip39.WordCount(line) != words {
				t.Errorf("line %d has %d words, want %d", i, bip39.WordCount(line), words)
			}
			if err := wl.Validate(line); err != nil {
				t.Errorf("line %d is not a valid mnemonic: %v", i, err)
			}
		}
	}
}

func TestMnemonicOnlyEveryLanguage(t *testing.T) {
	for _, lang := range bip39.Languages() {
		r := exec(t, "-mnemonic-only", "-count", "2", "-language", lang)
		if r.code != ExitOK {
			t.Fatalf("%s: exit = %d, stderr = %s", lang, r.code, r.stderr)
		}
		wl, err := bip39.Load(lang)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimRight(r.stdout, "\n"), "\n") {
			if err := wl.Validate(line); err != nil {
				t.Errorf("%s: invalid mnemonic: %v", lang, err)
			}
		}
	}
}

// TestMnemonicOnlyPhrasesFallback pins the Python compatibility quirk:
// -phrases is used when -count is absent.
func TestMnemonicOnlyPhrasesFallback(t *testing.T) {
	r := exec(t, "-mnemonic-only", "-phrases", "4")
	if r.code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	if got := strings.Count(r.stdout, "\n"); got != 4 {
		t.Errorf("got %d mnemonics, want 4", got)
	}

	// An explicit -count wins over -phrases.
	r = exec(t, "-mnemonic-only", "-phrases", "4", "-count", "2")
	if got := strings.Count(r.stdout, "\n"); got != 2 {
		t.Errorf("-count did not override -phrases: got %d lines", got)
	}
}

func TestMnemonicOnlyCountLimits(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"explicit zero", []string{"-mnemonic-only", "-count", "0"}, ExitUsage},
		{"negative", []string{"-mnemonic-only", "-count", "-5"}, ExitUsage},
		{"above maximum", []string{"-mnemonic-only", "-count", "10001"}, ExitUsage},
		{"large without output", []string{"-mnemonic-only", "-count", "1001"}, ExitUsage},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := exec(t, c.args...)
			if r.code != c.want {
				t.Errorf("exit = %d, want %d (stderr: %s)", r.code, c.want, r.stderr)
			}
			if r.stdout != "" {
				t.Errorf("stdout must be empty, got %q", r.stdout)
			}
		})
	}
}

func TestMnemonicOnlyLargeCountWithOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mnemonics.txt")
	r := exec(t, "-mnemonic-only", "-count", "1200", "-output", path)
	if r.code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 1200 {
		t.Fatalf("file has %d lines, want 1200", len(lines))
	}
	if r.stdout != "" {
		t.Errorf("with -output nothing should go to stdout, got %d bytes", len(r.stdout))
	}
}

// ---------------------------------------------------------------------------
// Auto-gen mode
// ---------------------------------------------------------------------------

func TestAutoGen(t *testing.T) {
	if testing.Short() {
		t.Skip("PBKDF2 runs")
	}
	r := exec(t, "-auto-gen", "-phrases", "2", "-password-length", "16", "-jobs", "2")
	if r.code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	for _, want := range []string{"Mnemonic 1:", "Password 1:", "Mnemonic 2:", "Password 2:"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, r.stdout)
		}
	}
}

func TestAutoGenOutputFile(t *testing.T) {
	if testing.Short() {
		t.Skip("PBKDF2 runs")
	}
	path := filepath.Join(t.TempDir(), "nested", "pairs.txt")
	r := exec(t, "-auto-gen", "-phrases", "2", "-password-length", "12", "-output", path)
	if r.code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("output file: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("file has %d lines, want 4 (mnemonic/password pairs)", len(lines))
	}
	wl, err := bip39.Load("english")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(lines); i += 2 {
		if err := wl.Validate(lines[i]); err != nil {
			t.Errorf("line %d is not a mnemonic: %v", i, err)
		}
		if len(lines[i+1]) != 12 {
			t.Errorf("line %d is not a 12-character password: %q", i+1, lines[i+1])
		}
	}
}

// TestOutputFilePermissions checks the hardening choice: output holds secrets,
// so it is created 0600 rather than the Python original's default 0644.
func TestOutputFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	path := filepath.Join(t.TempDir(), "secrets.txt")
	if r := exec(t, "-mnemonic-only", "-count", "3", "-output", path); r.code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("output file mode = %o, want 600", perm)
	}
}

func TestOutputFileTruncatesPreviousRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("stale\n", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := exec(t, "-mnemonic-only", "-count", "2", "-output", path); r.code != ExitOK {
		t.Fatalf("exit = %d", r.code)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "stale") {
		t.Error("output file was not truncated")
	}
}

func TestOutputPathErrors(t *testing.T) {
	dir := t.TempDir()
	// A directory cannot be opened for writing.
	r := exec(t, "-mnemonic-only", "-count", "2", "-output", dir)
	if r.code != ExitError {
		t.Errorf("writing to a directory: exit = %d, want %d", r.code, ExitError)
	}
	if !strings.Contains(r.stderr, "opening") && !strings.Contains(r.stderr, "creating") {
		t.Errorf("stderr = %q", r.stderr)
	}
}

// ---------------------------------------------------------------------------
// Argument validation
// ---------------------------------------------------------------------------

func TestUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"mnemonic with auto-gen", []string{"-mnemonic", validEN, "-auto-gen"}, "cannot use"},
		{"mnemonic with mnemonic-only", []string{"-mnemonic", validEN, "-mnemonic-only"}, "cannot use"},
		{"mnemonic with stdin", []string{"-mnemonic", validEN, "-mnemonic-stdin"}, "cannot use"},
		{"auto-gen with mnemonic-only", []string{"-auto-gen", "-mnemonic-only"}, "cannot use"},
		{"unknown language", []string{"-mnemonic-only", "-language", "klingon"}, "unsupported language"},
		{"empty language", []string{"-mnemonic-only", "-language", ""}, "unsupported language"},
		{"bad word count", []string{"-mnemonic-only", "-words", "13"}, "invalid -words"},
		{"zero words", []string{"-mnemonic-only", "-words", "0"}, "invalid -words"},
		{"negative words", []string{"-mnemonic-only", "-words", "-12"}, "invalid -words"},
		{"zero length", []string{"-mnemonic", validEN, "-password-length", "0"}, "must be positive"},
		{"negative length", []string{"-mnemonic", validEN, "-password-length", "-8"}, "must be positive"},
		{"length above max", []string{"-mnemonic", validEN, "-password-length", "257"}, "exceeds maximum"},
		{"zero phrases", []string{"-auto-gen", "-phrases", "0"}, "must be positive"},
		{"negative phrases", []string{"-auto-gen", "-phrases", "-3"}, "must be positive"},
		{"too many phrases", []string{"-auto-gen", "-phrases", "101"}, "exceeds maximum"},
		{"negative jobs", []string{"-auto-gen", "-jobs", "-2"}, "-jobs must be"},
		{"unknown flag", []string{"-nonsense"}, "flag provided but not defined"},
		{"non-numeric count", []string{"-mnemonic-only", "-count", "abc"}, "invalid value"},
		{"positional argument", []string{"-mnemonic-only", "stray"}, "unexpected positional"},
		{"bad log level", []string{"-mnemonic-only", "-log-level", "trace"}, "unknown log level"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := exec(t, c.args...)
			if r.code != ExitUsage {
				t.Fatalf("exit = %d, want %d (stderr: %s)", r.code, ExitUsage, r.stderr)
			}
			if !strings.Contains(r.stderr, c.want) {
				t.Errorf("stderr = %q, want it to mention %q", r.stderr, c.want)
			}
			if r.stdout != "" {
				t.Errorf("stdout must stay empty, got %q", r.stdout)
			}
		})
	}
}

// TestPasswordLengthIgnoredWithoutPasswords documents that -password-length is
// not validated in a mode that produces no passwords, matching the original.
func TestPasswordLengthIgnoredForMnemonicOnly(t *testing.T) {
	if r := exec(t, "-mnemonic-only", "-count", "1", "-password-length", "9999"); r.code != ExitOK {
		t.Errorf("exit = %d, stderr = %s", r.code, r.stderr)
	}
}

// ---------------------------------------------------------------------------
// Logging behaviour
// ---------------------------------------------------------------------------

func TestLogLevels(t *testing.T) {
	quiet := exec(t, "-mnemonic-only", "-log-level", "silent")
	if quiet.stderr != "" {
		t.Errorf("silent must produce no diagnostics, got %q", quiet.stderr)
	}
	if quiet.stdout == "" {
		t.Error("silent must still produce output")
	}

	info := exec(t, "-mnemonic-only")
	if !strings.Contains(info.stderr, "INFO") {
		t.Errorf("default level should log INFO, got %q", info.stderr)
	}
	if strings.Contains(info.stderr, "DEBUG") {
		t.Error("default level must not log DEBUG")
	}

	for _, flag := range []string{"-v", "-verbose"} {
		dbg := exec(t, "-mnemonic-only", flag)
		if !strings.Contains(dbg.stderr, "DEBUG") {
			t.Errorf("%s did not enable debug logging: %q", flag, dbg.stderr)
		}
	}

	explicit := exec(t, "-mnemonic-only", "-log-level", "debug")
	if !strings.Contains(explicit.stderr, "DEBUG") {
		t.Error("-log-level debug did not enable debug logging")
	}
}

func TestNoColorInRedirectedOutput(t *testing.T) {
	r := exec(t, "-mnemonic-only", "-v")
	if strings.Contains(r.stderr, "\033[") {
		t.Errorf("non-terminal stderr must not contain ANSI escapes:\n%q", r.stderr)
	}
	r = exec(t, "-mnemonic-only", "-no-color")
	if strings.Contains(r.stderr, "\033[") {
		t.Error("-no-color must suppress ANSI escapes")
	}
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

func TestCancellationExitCode(t *testing.T) {
	if testing.Short() {
		t.Skip("PBKDF2 runs")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var out, errb bytes.Buffer
	code := RunContext(ctx, []string{"-auto-gen", "-phrases", "50"}, strings.NewReader(""), &out, &errb)
	if code != ExitInterrupted {
		t.Errorf("exit = %d, want %d (stderr: %s)", code, ExitInterrupted, errb.String())
	}
}

func TestCancellationDuringMnemonicOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond)

	var out, errb bytes.Buffer
	code := RunContext(ctx, []string{"-mnemonic-only", "-count", "900", "-output",
		filepath.Join(t.TempDir(), "x.txt")}, strings.NewReader(""), &out, &errb)
	if code != ExitInterrupted {
		t.Errorf("exit = %d, want %d", code, ExitInterrupted)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func TestReadMnemonic(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"phrase\n", "phrase", false},
		{"phrase\r\n", "phrase", false},
		{"phrase", "phrase", false},
		{"a  b\n", "a  b", false}, // inner whitespace preserved verbatim
		{" phrase \n", " phrase ", false},
		{"\n", "", true},
		{"", "", true},
	}
	for _, c := range cases {
		got, err := readMnemonic(strings.NewReader(c.in))
		if (err != nil) != c.wantErr {
			t.Errorf("readMnemonic(%q) error = %v, wantErr = %v", c.in, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("readMnemonic(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestReadMnemonicIsBounded(t *testing.T) {
	// A hostile or accidental stream must not exhaust memory.
	huge := strings.NewReader(strings.Repeat("a", 1<<20))
	got, err := readMnemonic(huge)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) > 64*1024 {
		t.Errorf("read %d bytes, want the input to be capped", len(got))
	}
}

func TestOpenSinkDiscardsWithoutFallback(t *testing.T) {
	w, closeFn, err := openSink("", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	if w != io.Discard {
		t.Error("openSink with no path and no fallback should discard")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

// TestRunWrapper exercises the exported Run entry point, including the
// SIGINT/SIGTERM context installation that RunContext-based tests bypass.
func TestRunWrapper(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run([]string{"-version"}, &out, &errb); code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, errb.String())
	}
	if !strings.Contains(out.String(), buildinfo.Version) {
		t.Errorf("stdout = %q", out.String())
	}

	out.Reset()
	errb.Reset()
	if code := Run([]string{"-words", "13", "-mnemonic-only"}, &out, &errb); code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
}

// TestLogFormatJSON covers the structured output mode: every diagnostic line
// must be a self-contained JSON object, and generated output must stay on
// stdout in its normal form.
func TestLogFormatJSON(t *testing.T) {
	r := exec(t, "-mnemonic-only", "-count", "2", "-log-format", "json", "-v")
	if r.code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", r.code, r.stderr)
	}

	lines := strings.Split(strings.TrimRight(r.stderr, "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected several log records, got %q", r.stderr)
	}
	for _, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q (%v)", line, err)
		}
		for _, key := range []string{"time", "level", "msg"} {
			if _, ok := m[key]; !ok {
				t.Errorf("record %q has no %q key", line, key)
			}
		}
	}

	// Generated mnemonics are unaffected by the log format.
	if got := strings.Count(strings.TrimRight(r.stdout, "\n"), "\n") + 1; got != 2 {
		t.Errorf("stdout has %d mnemonics, want 2", got)
	}
}

func TestLogFormatInvalid(t *testing.T) {
	r := exec(t, "-mnemonic-only", "-log-format", "yaml")
	if r.code != ExitUsage {
		t.Errorf("exit = %d, want %d", r.code, ExitUsage)
	}
	if !strings.Contains(r.stderr, "unknown log format") {
		t.Errorf("stderr = %q", r.stderr)
	}
}

// TestStructuredAttributes checks that diagnostics carry real key/value pairs
// rather than values baked into the message text.
func TestStructuredAttributes(t *testing.T) {
	r := exec(t, "-mnemonic-only", "-count", "3", "-words", "24")
	for _, want := range []string{"count=3", "words=24", "language=english"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr missing attribute %q:\n%s", want, r.stderr)
		}
	}
}
