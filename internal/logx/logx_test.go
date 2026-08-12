package logx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/slogtest"
	"time"
)

var testTime = time.Date(2026, 8, 12, 10, 30, 0, 123000000, time.UTC)

// ---------------------------------------------------------------------------
// slog.Handler contract
// ---------------------------------------------------------------------------

// TestPrettyHandlerContract runs the standard library's own conformance suite
// against the pretty handler. It is the reason attribute and group handling is
// delegated to slog.TextHandler instead of being reimplemented: this suite
// checks empty-group elision, inline groups, LogValuer resolution, zero times
// and the WithAttrs/WithGroup interaction, all of which are easy to get wrong.
func TestPrettyHandlerContract(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf, Options{Level: slog.LevelDebug})

	results := func() []map[string]any {
		var records []map[string]any
		for _, line := range strings.Split(buf.String(), "\n") {
			if line == "" {
				continue
			}
			m, err := parsePretty(line)
			if err != nil {
				t.Fatalf("parsing %q: %v", line, err)
			}
			records = append(records, m)
		}
		return records
	}

	if err := slogtest.TestHandler(h, results); err != nil {
		t.Fatalf("pretty handler violates the slog.Handler contract:\n%v", err)
	}
}

// TestJSONHandlerContract covers the JSON mode through the same suite.
func TestJSONHandlerContract(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf, Options{Level: slog.LevelDebug, Format: FormatJSON})

	results := func() []map[string]any {
		var records []map[string]any
		for _, line := range strings.Split(buf.String(), "\n") {
			if line == "" {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Fatalf("parsing %q: %v", line, err)
			}
			records = append(records, m)
		}
		return records
	}

	if err := slogtest.TestHandler(h, results); err != nil {
		t.Fatalf("JSON handler violates the slog.Handler contract:\n%v", err)
	}
}

// parsePretty turns one output line back into the map slogtest expects.
//
// Like the standard library's own text parser it does not handle quoted keys
// or values, and it assumes the message contains no spaces. That is safe here:
// slogtest deliberately uses simple inputs so handler authors can test handler
// behaviour rather than parsing.
func parsePretty(line string) (map[string]any, error) {
	top := map[string]any{}

	rest := line
	// The timestamp is optional: a zero Record.Time must not be printed.
	if head, tail, found := strings.Cut(rest, " - "); found {
		if _, err := time.Parse(TimeFormat, head); err == nil {
			top[slog.TimeKey] = head
			rest = tail
		}
	}

	level, tail, found := strings.Cut(rest, " - ")
	if !found {
		return nil, fmt.Errorf("no level separator")
	}
	top[slog.LevelKey] = strings.TrimSpace(level)

	msg, attrs, _ := strings.Cut(tail, " ")
	top[slog.MessageKey] = msg

	for attrs != "" {
		var kv string
		kv, attrs, _ = strings.Cut(attrs, " ")
		key, value, found := strings.Cut(kv, "=")
		if !found {
			return nil, fmt.Errorf("no '=' in %q", kv)
		}
		// A dotted key denotes nesting: "g.k=v" becomes {"g": {"k": "v"}}.
		keys := strings.Split(key, ".")
		m := top
		for _, k := range keys[:len(keys)-1] {
			child, ok := m[k]
			if !ok {
				next := map[string]any{}
				m[k] = next
				m = next
				continue
			}
			next, ok := child.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%q is not a group", k)
			}
			m = next
		}
		m[keys[len(keys)-1]] = value
	}
	return top, nil
}

// ---------------------------------------------------------------------------
// Level and format parsing
// ---------------------------------------------------------------------------

func TestParseLevel(t *testing.T) {
	cases := []struct {
		in   string
		want slog.Level
	}{
		{"silent", LevelSilent}, {"off", LevelSilent}, {"none", LevelSilent},
		{"error", slog.LevelError}, {"ERROR", slog.LevelError}, {" error ", slog.LevelError},
		{"warn", slog.LevelWarn}, {"warning", slog.LevelWarn}, {"Warn", slog.LevelWarn},
		{"info", slog.LevelInfo}, {"INFO", slog.LevelInfo},
		{"debug", slog.LevelDebug}, {"verbose", slog.LevelDebug},
	}
	for _, c := range cases {
		got, err := ParseLevel(c.in)
		if err != nil {
			t.Errorf("ParseLevel(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"", "trace", "quiet", "12", "inf o"} {
		if _, err := ParseLevel(bad); err == nil {
			t.Errorf("ParseLevel(%q) accepted an unknown level", bad)
		}
	}
}

func TestParseLevelErrorMentionsChoices(t *testing.T) {
	_, err := ParseLevel("trace")
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"silent", "error", "warn", "info", "debug"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestParseFormat(t *testing.T) {
	cases := map[string]Format{
		"": FormatPretty, "pretty": FormatPretty, "text": FormatPretty,
		"PRETTY": FormatPretty, " json ": FormatJSON, "JSON": FormatJSON,
	}
	for in, want := range cases {
		got, err := ParseFormat(in)
		if err != nil {
			t.Errorf("ParseFormat(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseFormat(%q) = %v, want %v", in, got, want)
		}
	}
	for _, bad := range []string{"yaml", "logfmt", "xml"} {
		if _, err := ParseFormat(bad); err == nil {
			t.Errorf("ParseFormat(%q) accepted an unknown format", bad)
		}
	}
}

func TestLevelName(t *testing.T) {
	cases := map[slog.Level]string{
		slog.LevelDebug: "DEBUG",
		slog.LevelInfo:  "INFO",
		slog.LevelWarn:  "WARN",
		slog.LevelError: "ERROR",
		LevelSilent:     "SILENT",
		slog.Level(20):  "SILENT",
	}
	for lvl, want := range cases {
		if got := LevelName(lvl); got != want {
			t.Errorf("LevelName(%v) = %q, want %q", lvl, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------------

func TestLevelFiltering(t *testing.T) {
	cases := []struct {
		level slog.Level
		want  []string
		deny  []string
	}{
		{LevelSilent, nil, []string{"e-msg", "w-msg", "i-msg", "d-msg"}},
		{slog.LevelError, []string{"e-msg"}, []string{"w-msg", "i-msg", "d-msg"}},
		{slog.LevelWarn, []string{"e-msg", "w-msg"}, []string{"i-msg", "d-msg"}},
		{slog.LevelInfo, []string{"e-msg", "w-msg", "i-msg"}, []string{"d-msg"}},
		{slog.LevelDebug, []string{"e-msg", "w-msg", "i-msg", "d-msg"}, nil},
	}
	for _, format := range []Format{FormatPretty, FormatJSON} {
		for _, c := range cases {
			t.Run(string(format)+"/"+LevelName(c.level), func(t *testing.T) {
				var buf bytes.Buffer
				l := New(&buf, Options{Level: c.level, Format: format})
				l.Error("e-msg")
				l.Warn("w-msg")
				l.Info("i-msg")
				l.Debug("d-msg")

				out := buf.String()
				for _, want := range c.want {
					if !strings.Contains(out, want) {
						t.Errorf("missing %q in %q", want, out)
					}
				}
				for _, deny := range c.deny {
					if strings.Contains(out, deny) {
						t.Errorf("unexpected %q in %q", deny, out)
					}
				}
			})
		}
	}
}

func TestEnabled(t *testing.T) {
	ctx := context.Background()
	l := New(io.Discard, Options{Level: slog.LevelInfo})

	if !l.Enabled(ctx, slog.LevelInfo) || !l.Enabled(ctx, slog.LevelError) {
		t.Error("info logger must enable info and error")
	}
	if l.Enabled(ctx, slog.LevelDebug) {
		t.Error("info logger must not enable debug")
	}

	silent := New(io.Discard, Options{Level: LevelSilent})
	for _, lvl := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
		if silent.Enabled(ctx, lvl) {
			t.Errorf("silent logger must not enable %v", lvl)
		}
	}
}

// ---------------------------------------------------------------------------
// Output shape
// ---------------------------------------------------------------------------

func TestPrettyFormat(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf, Options{Level: slog.LevelDebug})

	r := slog.NewRecord(testTime, slog.LevelInfo, "generating mnemonics", 0)
	r.AddAttrs(slog.Int("count", 7), slog.String("language", "english"))
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	want := "2026-08-12 10:30:00.123 - INFO  - generating mnemonics count=7 language=english\n"
	if got := buf.String(); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestPrettyFormatWithoutAttrs(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf, Options{Level: slog.LevelDebug})

	r := slog.NewRecord(testTime, slog.LevelWarn, "interrupted", 0)
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	want := "2026-08-12 10:30:00.123 - WARN  - interrupted\n"
	if got := buf.String(); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if strings.HasSuffix(buf.String(), " \n") {
		t.Error("a record without attributes must not leave a trailing space")
	}
}

func TestPrettyZeroTimeIsOmitted(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf, Options{Level: slog.LevelDebug})

	r := slog.NewRecord(time.Time{}, slog.LevelInfo, "no clock", 0)
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "INFO  - no clock\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestPrettyGroupsAndWith(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, Options{Level: slog.LevelDebug}).
		With(slog.String("language", "french")).
		WithGroup("entropy")

	r := slog.NewRecord(testTime, slog.LevelDebug, "derived", 0)
	_ = l.Handler().Handle(context.Background(), r)

	out := buf.String()
	if !strings.Contains(out, "language=french") {
		t.Errorf("With attribute missing: %q", out)
	}

	buf.Reset()
	l.Debug("derived", slog.Int("bits", 128))
	if out := buf.String(); !strings.Contains(out, "entropy.bits=128") {
		t.Errorf("group prefix missing: %q", out)
	}
}

// TestDerivedHandlersReuseTheReceiver checks the cheap paths: a no-op
// WithAttrs or WithGroup must not allocate a new handler, and must not change
// behaviour.
func TestDerivedHandlersReuseTheReceiver(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf, Options{Level: slog.LevelDebug})

	if got := h.WithAttrs(nil); got != h {
		t.Error("WithAttrs(nil) should return the receiver")
	}
	if got := h.WithAttrs([]slog.Attr{}); got != h {
		t.Error("WithAttrs(empty) should return the receiver")
	}
	if got := h.WithGroup(""); got != h {
		t.Error(`WithGroup("") should return the receiver`)
	}

	r := slog.NewRecord(testTime, slog.LevelInfo, "msg", 0)
	if err := h.WithGroup("").Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "2026-08-12 10:30:00.123 - INFO  - msg\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestColorOutput(t *testing.T) {
	var buf bytes.Buffer
	h := NewHandler(&buf, Options{Level: slog.LevelDebug, Color: true})

	r := slog.NewRecord(testTime, slog.LevelError, "boom", 0)
	r.AddAttrs(slog.Int("code", 1))
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	for _, want := range []string{ansiBlue, ansiRed, ansiDim, ansiReset} {
		if !strings.Contains(out, want) {
			t.Errorf("coloured output missing escape %q: %q", want, out)
		}
	}
	if !strings.HasSuffix(out, "\n") {
		t.Error("line must end with a newline")
	}

	buf.Reset()
	plain := NewHandler(&buf, Options{Level: slog.LevelDebug})
	if err := plain.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\033[") {
		t.Errorf("plain output must not contain ANSI escapes: %q", buf.String())
	}
}

func TestLevelColors(t *testing.T) {
	cases := map[slog.Level]string{
		slog.LevelDebug: ansiCyan,
		slog.LevelInfo:  ansiGreen,
		slog.LevelWarn:  ansiYellow,
		slog.LevelError: ansiRed,
	}
	for lvl, want := range cases {
		if got := levelColor(lvl); got != want {
			t.Errorf("levelColor(%v) = %q, want %q", lvl, got, want)
		}
	}
}

func TestJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, Options{Level: slog.LevelDebug, Format: FormatJSON})
	l.Info("generating mnemonics", slog.Int("count", 7))

	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("output is not valid JSON: %v (%q)", err, buf.String())
	}
	if m["msg"] != "generating mnemonics" {
		t.Errorf("msg = %v", m["msg"])
	}
	if m["count"] != float64(7) {
		t.Errorf("count = %v (%T), want 7", m["count"], m["count"])
	}
	if m["level"] != "INFO" {
		t.Errorf("level = %v", m["level"])
	}
}

// ---------------------------------------------------------------------------
// Robustness
// ---------------------------------------------------------------------------

func TestNilWriterIsSafe(t *testing.T) {
	l := New(nil, Options{Level: slog.LevelDebug})
	l.Error("no writer")
	l.Debug("still no writer", slog.Int("k", 1))
}

func TestDiscard(t *testing.T) {
	l := Discard()
	if l.Enabled(context.Background(), slog.LevelError) {
		t.Error("Discard must not enable any level")
	}
	l.Error("dropped")
}

// TestWriteErrorIsReported checks that a failing destination surfaces as an
// error rather than being swallowed.
func TestWriteErrorIsReported(t *testing.T) {
	h := NewHandler(failingWriter{}, Options{Level: slog.LevelDebug})
	r := slog.NewRecord(testTime, slog.LevelInfo, "msg", 0)

	err := h.Handle(context.Background(), r)
	if err == nil {
		t.Fatal("expected a write error")
	}
	if !errors.Is(err, errWrite) {
		t.Errorf("error = %v, want it to wrap errWrite", err)
	}
}

var errWrite = errors.New("write failed")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWrite }

// TestConcurrentLogging checks that records from parallel goroutines are not
// interleaved, including across handlers derived with With and WithGroup,
// which share one mutex and one destination.
func TestConcurrentLogging(t *testing.T) {
	var buf bytes.Buffer
	base := New(&buf, Options{Level: slog.LevelDebug})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				base.Info("line", slog.Int("i", i))
			case 1:
				base.With(slog.String("scope", "a")).Info("line", slog.Int("i", i))
			default:
				base.WithGroup("g").Info("line", slog.Int("i", i))
			}
		}(i)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 50 {
		t.Fatalf("got %d lines, want 50 (interleaved writes?)", len(lines))
	}
	for _, line := range lines {
		if !strings.Contains(line, " - INFO  - line ") {
			t.Fatalf("malformed line: %q", line)
		}
	}
}

func TestDurationAttr(t *testing.T) {
	a := Duration("seed", 1234*time.Microsecond)
	if a.Key != "seed" {
		t.Errorf("key = %q", a.Key)
	}
	if got := a.Value.String(); got != "1ms" {
		t.Errorf("value = %q, want 1ms", got)
	}
}

func TestColorEnabled(t *testing.T) {
	var buf bytes.Buffer

	if ColorEnabled(&buf, false) {
		t.Error("a non-terminal writer must not get colour")
	}
	if ColorEnabled(&buf, true) {
		t.Error("disabled must stay disabled")
	}

	f, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if ColorEnabled(f, false) {
		t.Error("a regular file must not get colour")
	}

	t.Setenv("NO_COLOR", "1")
	if dev, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0); err == nil {
		defer dev.Close()
		if ColorEnabled(dev, false) {
			t.Error("NO_COLOR must disable colour")
		}
	}

	closed, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	if ColorEnabled(closed, false) {
		t.Error("an unusable file must not get colour")
	}
}

func BenchmarkPrettyHandler(b *testing.B) {
	l := New(io.Discard, Options{Level: slog.LevelDebug})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		l.Info("generating mnemonics", slog.Int("count", 7), slog.String("language", "english"))
	}
}

func BenchmarkDisabledLevel(b *testing.B) {
	l := New(io.Discard, Options{Level: slog.LevelInfo})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		l.Debug("skipped", slog.Int("count", 7))
	}
}

// brokenHandler drops WithGroup, which is one of the mistakes slogtest exists
// to catch.
type brokenHandler struct{ slog.Handler }

func (b brokenHandler) WithGroup(string) slog.Handler { return b }

// TestConformanceSuiteIsNotVacuous guards the guard: it proves that the
// parsing in TestPrettyHandlerContract really feeds slogtest, so a passing
// contract test means something. Without this, a parser that silently
// returned empty results would make the conformance test pass for free.
func TestConformanceSuiteIsNotVacuous(t *testing.T) {
	var buf bytes.Buffer
	h := brokenHandler{NewHandler(&buf, Options{Level: slog.LevelDebug})}

	results := func() []map[string]any {
		var records []map[string]any
		for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
			if line == "" {
				continue
			}
			m, err := parsePretty(line)
			if err != nil {
				return records
			}
			records = append(records, m)
		}
		return records
	}

	if err := slogtest.TestHandler(h, results); err == nil {
		t.Fatal("slogtest accepted a handler that ignores WithGroup")
	}
}
