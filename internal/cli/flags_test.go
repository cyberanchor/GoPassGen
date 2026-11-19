package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"strings"
	"testing"
)

const sensitivePhrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"

func parseAndValidate(args ...string) (*options, error) {
	opts, _, err := parse(args)
	if err != nil {
		return opts, err
	}
	return opts, validateModes(opts)
}

// The values are spelled out on purpose: they are a documented interface, so a
// test comparing against the constants would not notice them changing.
func TestExitCodesHaveDocumentedValues(t *testing.T) {
	for name, c := range map[string][2]int{
		"ok":          {ExitOK, 0},
		"error":       {ExitError, 1},
		"usage":       {ExitUsage, 2},
		"interrupted": {ExitInterrupted, 130},
	} {
		if c[0] != c[1] {
			t.Errorf("%s = %d, want %d", name, c[0], c[1])
		}
	}
}

func TestNumbersAreReadAsDecimal(t *testing.T) {
	opts, err := parseAndValidate("-mnemonic", validEN, "-password-length", "016")
	if err != nil {
		t.Fatal(err)
	}
	if opts.passwordLength != 16 {
		t.Errorf("-password-length 016 = %d, want 16", opts.passwordLength)
	}
	opts, err = parseAndValidate("-mnemonic-only", "-count", "010", "-words", "012")
	if err != nil {
		t.Fatal(err)
	}
	if opts.count != 10 || opts.words != 12 {
		t.Errorf("-count 010 = %d, -words 012 = %d, want 10 and 12", opts.count, opts.words)
	}
	if _, err := parseAndValidate("-mnemonic-only", "-words", "014"); err == nil {
		t.Error("-words 014 means 14, which is not a valid word count")
	}
}

func TestMalformedNumbersAreRejected(t *testing.T) {
	for _, value := range []string{
		"0x10", "0X10", "0b1100", "0o14", "1_000", "+5", " 5", "5 ", "", "5.0", "1e3", "٣", "abc",
		"99999999999999999999",
	} {
		r := exec(t, "-mnemonic-only", "-count", value)
		if r.code != 2 || r.stdout != "" {
			t.Errorf("-count %q: exit = %d, stdout = %q", value, r.code, r.stdout)
		}
	}
}

// TestNegativeValuesAreRejectedEverywhere includes modes that ignore the option:
// such a value used to pass unnoticed there.
func TestNegativeValuesAreRejectedEverywhere(t *testing.T) {
	modes := [][]string{
		{"-mnemonic-only"},
		{"-auto-gen"},
		{"-mnemonic", validEN},
		{"-mnemonic-stdin"},
		{"-version"},
		{"-self-test"},
		{},
	}
	for _, name := range []string{"count", "phrases", "words", "password-length", "jobs"} {
		for _, value := range []string{"-1", "-0", "-999999999999999999999"} {
			for _, mode := range modes {
				args := append(append([]string(nil), mode...), "-"+name, value)
				r := execStdin(t, validEN, args...)
				if r.code != 2 {
					t.Errorf("%v: exit = %d, want 2", args, r.code)
				}
				if !strings.Contains(r.stderr, "negative values are not allowed") {
					t.Errorf("%v: stderr = %q", args, firstLine(r.stderr))
				}
				if r.stdout != "" {
					t.Errorf("%v: stdout = %q", args, r.stdout)
				}
			}
		}
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

func TestLimits(t *testing.T) {
	const out = "file.txt"
	cases := []struct {
		name string
		args []string
		ok   bool
	}{
		{"count 1000 needs no file", []string{"-mnemonic-only", "-count", "1000"}, true},
		{"count 1001 needs a file", []string{"-mnemonic-only", "-count", "1001"}, false},
		{"count 1001 with a file", []string{"-mnemonic-only", "-count", "1001", "-output", out}, true},
		{"count at maximum", []string{"-mnemonic-only", "-count", "10000", "-output", out}, true},
		{"count above maximum", []string{"-mnemonic-only", "-count", "10001", "-output", out}, false},
		{"count zero", []string{"-mnemonic-only", "-count", "0"}, false},
		{"phrases fallback at limit", []string{"-mnemonic-only", "-phrases", "1000"}, true},
		{"phrases fallback above limit", []string{"-mnemonic-only", "-phrases", "1001"}, false},
		{"phrases at maximum", []string{"-auto-gen", "-phrases", "100"}, true},
		{"phrases above maximum", []string{"-auto-gen", "-phrases", "101"}, false},
		{"phrases zero", []string{"-auto-gen", "-phrases", "0"}, false},
		{"length one", []string{"-auto-gen", "-password-length", "1"}, true},
		{"length at maximum", []string{"-auto-gen", "-password-length", "256"}, true},
		{"length above maximum", []string{"-auto-gen", "-password-length", "257"}, false},
		{"length zero", []string{"-auto-gen", "-password-length", "0"}, false},
		{"jobs zero means automatic", []string{"-auto-gen", "-jobs", "0"}, true},
		{"empty output name", []string{"-mnemonic-only", "-output", ""}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseAndValidate(c.args...)
			if (err == nil) != c.ok {
				t.Errorf("err = %v, want ok = %v", err, c.ok)
			}
			var ue usageError
			if err != nil && !errors.As(err, &ue) {
				t.Errorf("%v is not a usage error", err)
			}
		})
	}
	for _, words := range []string{"12", "15", "18", "21", "24"} {
		if _, err := parseAndValidate("-mnemonic-only", "-words", words); err != nil {
			t.Errorf("-words %s: %v", words, err)
		}
	}
	for _, words := range []string{"0", "11", "13", "25"} {
		if _, err := parseAndValidate("-mnemonic-only", "-words", words); err == nil {
			t.Errorf("-words %s was accepted", words)
		}
	}
}

func TestOptionsWithoutEffectAreRejected(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"-auto-gen", "-count", "3"}, "-count applies only"},
		{[]string{"-mnemonic", validEN, "-count", "3"}, "-count applies only"},
		{[]string{"-mnemonic-stdin", "-phrases", "3"}, "-phrases applies only"},
		{[]string{"-mnemonic", validEN, "-words", "24"}, "-words applies only"},
		{[]string{"-mnemonic-only", "-password-length", "16"}, "-password-length applies only"},
		{[]string{"-mnemonic-only", "-jobs", "2"}, "-jobs applies only"},
		{[]string{"-mnemonic-stdin", "-jobs", "2"}, "-jobs applies only"},
	}
	for _, c := range cases {
		r := execStdin(t, validEN, c.args...)
		if r.code != 2 || !strings.Contains(r.stderr, c.want) || r.stdout != "" {
			t.Errorf("%v: exit = %d, stderr = %q", c.args, r.code, firstLine(r.stderr))
		}
	}
}

func TestInfoModesTakeNoWorkOptions(t *testing.T) {
	for _, mode := range []string{"-version", "-self-test"} {
		for _, extra := range [][]string{
			{"-mnemonic", validEN}, {"-mnemonic-stdin"}, {"-auto-gen"}, {"-mnemonic-only"}, {"-count", "1"},
			{"-phrases", "1"}, {"-words", "12"}, {"-password-length", "8"}, {"-language", "french"},
			{"-output", "x"}, {"-jobs", "1"},
		} {
			args := append([]string{mode}, extra...)
			if r := exec(t, args...); r.code != 2 || r.stdout != "" {
				t.Errorf("%v: exit = %d, stdout = %q", args, r.code, r.stdout)
			}
		}
	}
	if r := exec(t, "-version", "-self-test"); r.code != 2 {
		t.Errorf("-version -self-test: exit = %d", r.code)
	}
	r := exec(t, "-version", "-no-color", "-case-sensitive", "-v", "-log-level", "debug", "-log-format", "json")
	if r.code != 0 {
		t.Errorf("logging flags must stay usable with -version: exit = %d, stderr = %s", r.code, r.stderr)
	}
}

func TestVerboseContradictsOtherLogLevels(t *testing.T) {
	for _, flagName := range []string{"-v", "-verbose"} {
		if r := exec(t, "-mnemonic-only", flagName, "-log-level", "error"); r.code != 2 || r.stdout != "" {
			t.Errorf("%s -log-level error: exit = %d", flagName, r.code)
		}
		if r := exec(t, "-mnemonic-only", flagName, "-log-level", "debug"); r.code != 0 {
			t.Errorf("%s -log-level debug: exit = %d", flagName, r.code)
		}
	}
}

// misuses are mistakes that put a phrase where it does not belong.
func misuses() map[string][]string {
	m := map[string][]string{
		"flag forgotten":   {sensitivePhrase},
		"quotes forgotten": append([]string{"-mnemonic"}, strings.Fields(sensitivePhrase)...),
		"after a mode":     {"-mnemonic-only", sensitivePhrase},
		"as a flag":        {"-" + strings.ReplaceAll(sensitivePhrase, " ", "-")},
		"bad syntax":       {"---" + sensitivePhrase},
		"as a bool value":  {"-auto-gen=" + sensitivePhrase},
		"unknown value":    {"-unknown=" + sensitivePhrase},
	}
	for _, name := range []string{"language", "words", "count", "phrases", "password-length", "jobs", "log-level", "log-format"} {
		m["in -"+name] = []string{"-mnemonic-only", "-" + name, sensitivePhrase}
	}
	return m
}

func TestCaseSensitiveHidesTypedValues(t *testing.T) {
	for name, args := range misuses() {
		for _, spelling := range []string{"-case-sensitive", "--case-sensitive", "-case-sensitive=true"} {
			for _, format := range []string{"pretty", "json"} {
				logging := []string{"-log-format", format}
				if strings.Contains(name, "-log-format") {
					logging = nil
				}
				for _, full := range [][]string{
					append(append([]string{spelling}, logging...), args...),
					append(append(append([]string(nil), args...), logging...), spelling),
				} {
					r := execStdin(t, "", full...)
					if r.code != 2 {
						t.Errorf("%s %v: exit = %d, want 2", name, full, r.code)
					}
					for _, word := range []string{"sausage", "winner", "yellow"} {
						if strings.Contains(r.stderr, word) {
							t.Errorf("%s: %q leaked with %v:\n%s", name, word, full, firstLine(r.stderr))
						}
					}
				}
			}
		}
	}
}

// TestValuesAreShownByDefault pins the agreed default: without the flag an error
// names the offending value, which is what makes it useful.
func TestValuesAreShownByDefault(t *testing.T) {
	for _, args := range [][]string{
		{sensitivePhrase},
		{"-case-sensitive=false", sensitivePhrase},
		{"-case-sensitive", "-case-sensitive=false", sensitivePhrase},
		{"-mnemonic-only", "-language", sensitivePhrase},
	} {
		if r := exec(t, args...); r.code != 2 || !strings.Contains(r.stderr, "sausage") {
			t.Errorf("%v: exit = %d, stderr = %q", args, r.code, firstLine(r.stderr))
		}
	}
}

// TestCaseSensitiveWorksEvenWhenSwallowedAsAValue: here the parser reads the flag
// as the value of -mnemonic, but the user clearly asked for it.
func TestCaseSensitiveWorksEvenWhenSwallowedAsAValue(t *testing.T) {
	r := exec(t, "-mnemonic", "-case-sensitive", sensitivePhrase)
	if r.code != 2 || strings.Contains(r.stderr, "sausage") {
		t.Errorf("exit = %d, stderr = %q", r.code, firstLine(r.stderr))
	}
}

func TestCaseSensitiveKeepsTheReason(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"-count", "-5", "-mnemonic-only"}, "invalid value <hidden> for -count: negative values are not allowed"},
		{[]string{"-count", "x", "-mnemonic-only"}, "invalid value <hidden> for -count: must be a decimal integer"},
		{[]string{"-auto-gen=x"}, "invalid value <hidden> for -auto-gen"},
		{[]string{"-count"}, "flag needs an argument: -count"},
		{[]string{"-nonsense"}, "unknown or malformed flag <hidden>"},
		{[]string{"-mnemonic-only", "-language", "x"}, "unsupported language <hidden>"},
		{[]string{"-mnemonic-only", "-log-level", "x"}, "unknown log level <hidden>"},
		{[]string{"-mnemonic-only", "-log-format", "x"}, "unknown log format <hidden>"},
		{[]string{"stray"}, "unexpected positional argument <hidden>"},
	}
	for _, c := range cases {
		r := exec(t, append([]string{"-case-sensitive"}, c.args...)...)
		if r.code != 2 || !strings.Contains(r.stderr, c.want) {
			t.Errorf("%v: exit = %d, stderr = %q, want %q", c.args, r.code, firstLine(r.stderr), c.want)
		}
	}
}

// TestFlagTakenAsValueIsNotCalledNegative covers a forgotten value: the next flag
// becomes the value, and "negative" would be a confusing thing to say about it.
func TestFlagTakenAsValueIsNotCalledNegative(t *testing.T) {
	r := exec(t, "-count", "-mnemonic-only")
	if r.code != 2 || !strings.Contains(r.stderr, "must be a decimal integer") {
		t.Errorf("exit = %d, stderr = %q", r.code, firstLine(r.stderr))
	}
}

func TestHideFlagErrorNeverTrustsTheMessage(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	fs.Bool("known", false, "")
	cases := []struct{ in, want string }{
		{`invalid value "a for flag -known: b" for flag -nope: parse error`, "unknown or malformed flag <hidden>"},
		{`invalid value "secret" for flag -known: parse error`, "invalid value <hidden> for -known: parse error"},
		{`invalid boolean value "secret" for -known: parse error`, "invalid value <hidden> for -known: parse error"},
		{"flag provided but not defined: -secret", "unknown or malformed flag <hidden>"},
		{"bad flag syntax: ---secret", "unknown or malformed flag <hidden>"},
		{"a future message about secret", "unknown or malformed flag <hidden>"},
		{"flag needs an argument: -known", "flag needs an argument: -known"},
	}
	for _, c := range cases {
		if got := hideFlagError(fs, errors.New(c.in)).Error(); got != c.want {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParserAlwaysFinishes(t *testing.T) {
	for _, args := range [][]string{
		{"---x"}, {"-="}, {"--=x"}, {"---", "---"}, {"--"}, {"--", "-x"}, {"-"}, {"", ""}, {"-count"},
		{"x", "---y", "z"}, {"-h", "---x"},
	} {
		parse(args) // a regression here shows up as a hang
	}
}

func TestErrorsAreReportedOnce(t *testing.T) {
	for _, args := range [][]string{{"-nonsense"}, {"-count", "x"}, {"stray"}, {"-mnemonic-only", "-words", "13"}} {
		r := exec(t, args...)
		if r.code != 2 {
			t.Errorf("%v: exit = %d", args, r.code)
		}
		if n := strings.Count(r.stderr, "Usage:"); n != 1 {
			t.Errorf("%v: usage printed %d times", args, n)
		}
		if n := strings.Count(r.stderr, "ERROR"); n != 1 {
			t.Errorf("%v: %d error records", args, n)
		}
	}
}

func TestSilentPrintsNothingForUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"-log-level", "silent", "-mnemonic-only", "-words", "13"},
		{"-nonsense", "-log-level", "silent"},
		{"stray", "-log-level", "silent"},
	} {
		if r := exec(t, args...); r.code != 2 || r.stderr != "" {
			t.Errorf("%v: exit = %d, stderr = %q", args, r.code, firstLine(r.stderr))
		}
	}
}

func TestJSONModeEmitsOnlyJSON(t *testing.T) {
	for _, args := range [][]string{
		{"-log-format", "json", "-mnemonic-only", "-words", "13"},
		{"-nonsense", "-log-format", "json"},
		{"stray", "-log-format", "json"},
		{"-log-format", "json", "-count", "x"},
		{"-log-format", "json", "-log-level", "bogus", "-mnemonic-only"},
	} {
		r := exec(t, args...)
		if r.code != 2 || r.stderr == "" {
			t.Errorf("%v: exit = %d, stderr = %q", args, r.code, r.stderr)
		}
		for _, line := range strings.Split(strings.TrimRight(r.stderr, "\n"), "\n") {
			var record map[string]any
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				t.Errorf("%v: not JSON: %q", args, line)
			} else if record["level"] != "ERROR" {
				t.Errorf("%v: record %v", args, record)
			}
		}
	}
}

func TestHelpIsPrintedOnce(t *testing.T) {
	r := exec(t, "-h", "-log-format", "json")
	if r.code != 0 || strings.Count(r.stderr, "Usage:") != 1 {
		t.Errorf("exit = %d, usage printed %d times", r.code, strings.Count(r.stderr, "Usage:"))
	}
	if !strings.Contains(r.stderr, "-case-sensitive") {
		t.Error("help must document -case-sensitive")
	}
}
