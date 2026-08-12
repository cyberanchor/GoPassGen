// Package logx wires log/slog into GoPassGen.
//
// The logging itself is standard library: callers hold a *slog.Logger and use
// structured attributes. This package only supplies what slog deliberately
// leaves out of its standard handlers:
//
//   - a human-readable "timestamp - LEVEL - message key=value" layout that
//     matches the PyPassGen output people are used to;
//   - ANSI colour, enabled only for a real terminal and never when NO_COLOR
//     is set;
//   - a "silent" level, level parsing for the CLI flag, and a JSON mode for
//     machine consumption.
//
// Attribute and group handling is delegated to slog.TextHandler, so the subtle
// parts of the slog.Handler contract — WithAttrs, WithGroup, empty group
// elision, LogValuer resolution — come from the standard library rather than
// from hand-written code. The handler is verified against testing/slogtest.
//
// Nothing in this package formats a secret. Callers must pass sizes, durations
// and counts, never a mnemonic, seed, key or password.
package logx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// LevelSilent is above every standard level, so no record is ever emitted.
// slog.Level is an int where higher means more severe, so a level above
// slog.LevelError is the idiomatic way to disable output entirely.
const LevelSilent = slog.Level(12)

// TimeFormat is the layout used by the pretty handler.
const TimeFormat = "2006-01-02 15:04:05.000"

// Format selects the output encoding.
type Format string

const (
	// FormatPretty is the default human-readable layout.
	FormatPretty Format = "pretty"
	// FormatJSON emits one JSON object per record, via slog.JSONHandler.
	FormatJSON Format = "json"
)

// ParseFormat maps a user-supplied string to a Format.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "pretty", "text":
		return FormatPretty, nil
	case "json":
		return FormatJSON, nil
	default:
		return FormatPretty, fmt.Errorf("unknown log format %q (want: pretty, json)", s)
	}
}

// ParseLevel maps a user-supplied string to a slog.Level.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "silent", "off", "none":
		return LevelSilent, nil
	case "error":
		return slog.LevelError, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "info":
		return slog.LevelInfo, nil
	case "debug", "verbose":
		return slog.LevelDebug, nil
	default:
		return slog.LevelInfo, fmt.Errorf(
			"unknown log level %q (want: silent, error, warn, info, debug)", s)
	}
}

// LevelName renders a level for output, adding the name slog does not know.
func LevelName(l slog.Level) string {
	if l >= LevelSilent {
		return "SILENT"
	}
	return l.String()
}

// Options configures a logger.
type Options struct {
	// Level is the minimum severity to emit. The zero value is slog.LevelInfo.
	Level slog.Level
	// Format selects the encoding. The zero value is FormatPretty.
	Format Format
	// Color enables ANSI colour. Only honoured by FormatPretty; use
	// ColorEnabled to decide it from the writer.
	Color bool
	// AddSource includes the caller's file and line. Off by default: it is
	// noise for a CLI, but useful when chasing a bug.
	AddSource bool
}

// New returns a *slog.Logger writing to w.
//
// w may be nil, in which case the logger discards everything, which keeps
// callers free of nil checks.
func New(w io.Writer, opts Options) *slog.Logger {
	return slog.New(NewHandler(w, opts))
}

// Discard returns a logger that drops every record.
func Discard() *slog.Logger {
	return slog.New(NewHandler(io.Discard, Options{Level: LevelSilent}))
}

// NewHandler builds the slog.Handler behind New.
func NewHandler(w io.Writer, opts Options) slog.Handler {
	if w == nil {
		w = io.Discard
	}
	if opts.Format == FormatJSON {
		return slog.NewJSONHandler(w, &slog.HandlerOptions{
			Level:     opts.Level,
			AddSource: opts.AddSource,
		})
	}
	return newPrettyHandler(w, opts)
}

// ---------------------------------------------------------------------------
// Pretty handler
// ---------------------------------------------------------------------------

// sink is the state shared by a handler and every handler derived from it
// through WithAttrs and WithGroup. The mutex guards both the scratch buffer
// and the destination, so concurrent records cannot interleave.
type sink struct {
	mu  sync.Mutex
	buf bytes.Buffer
	out io.Writer
}

// prettyHandler renders records as "timestamp - LEVEL - message key=value".
//
// It owns only the prefix. Attributes and groups are formatted by an embedded
// slog.TextHandler whose built-in time, level and message attributes are
// removed, leaving exactly the "key=value" tail.
type prettyHandler struct {
	sink  *sink
	inner slog.Handler
	level slog.Level
	color bool
}

func newPrettyHandler(w io.Writer, opts Options) *prettyHandler {
	s := &sink{out: w}
	return &prettyHandler{
		sink:  s,
		inner: slog.NewTextHandler(&s.buf, innerOptions(opts)),
		level: opts.Level,
		color: opts.Color,
	}
}

// innerOptions configures the embedded TextHandler to emit attributes only.
//
// The built-in keys are dropped at the top level because this handler prints
// them itself; an attribute that happens to be named "time", "level" or "msg"
// inside a group is left untouched.
func innerOptions(opts Options) *slog.HandlerOptions {
	return &slog.HandlerOptions{
		// The inner handler must never filter: the outer Enabled has already
		// decided, and the inner one has no notion of LevelSilent.
		Level:     slog.LevelDebug - 1000,
		AddSource: opts.AddSource,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 {
				switch a.Key {
				case slog.TimeKey, slog.LevelKey, slog.MessageKey:
					return slog.Attr{}
				}
			}
			return a
		},
	}
}

// Enabled implements slog.Handler.
func (h *prettyHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

// WithAttrs implements slog.Handler.
func (h *prettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	return h.derive(h.inner.WithAttrs(attrs))
}

// WithGroup implements slog.Handler.
func (h *prettyHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return h.derive(h.inner.WithGroup(name))
}

// derive returns a copy bound to a new inner handler. The sink is shared on
// purpose: every derived handler must serialise on the same mutex and write
// to the same destination.
func (h *prettyHandler) derive(inner slog.Handler) *prettyHandler {
	return &prettyHandler{
		sink:  h.sink,
		inner: inner,
		level: h.level,
		color: h.color,
	}
}

// Handle implements slog.Handler.
func (h *prettyHandler) Handle(ctx context.Context, r slog.Record) error {
	h.sink.mu.Lock()
	defer h.sink.mu.Unlock()

	h.sink.buf.Reset()
	if err := h.inner.Handle(ctx, r); err != nil {
		return fmt.Errorf("formatting attributes: %w", err)
	}
	attrs := strings.TrimRight(h.sink.buf.String(), "\n")

	if _, err := io.WriteString(h.sink.out, h.format(r, attrs)); err != nil {
		return fmt.Errorf("writing log record: %w", err)
	}
	return nil
}

const (
	ansiReset  = "\033[0m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiGreen  = "\033[32m"
	ansiDim    = "\033[2m"
)

func levelColor(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return ansiRed
	case l >= slog.LevelWarn:
		return ansiYellow
	case l >= slog.LevelInfo:
		return ansiGreen
	default:
		return ansiCyan
	}
}

// format builds one output line, including the trailing newline.
// A zero Record.Time is omitted rather than substituted, as slog requires.
func (h *prettyHandler) format(r slog.Record, attrs string) string {
	var b strings.Builder

	if !r.Time.IsZero() {
		ts := r.Time.Format(TimeFormat)
		if h.color {
			b.WriteString(ansiBlue)
			b.WriteString(ts)
			b.WriteString(ansiReset)
		} else {
			b.WriteString(ts)
		}
		b.WriteString(" - ")
	}

	name := fmt.Sprintf("%-5s", LevelName(r.Level))
	if h.color {
		b.WriteString(levelColor(r.Level))
		b.WriteString(name)
		b.WriteString(ansiReset)
	} else {
		b.WriteString(name)
	}

	b.WriteString(" - ")
	b.WriteString(r.Message)

	if attrs != "" {
		b.WriteString(" ")
		if h.color {
			b.WriteString(ansiDim)
			b.WriteString(attrs)
			b.WriteString(ansiReset)
		} else {
			b.WriteString(attrs)
		}
	}

	b.WriteString("\n")
	return b.String()
}

// ---------------------------------------------------------------------------
// Terminal detection
// ---------------------------------------------------------------------------

// ColorEnabled decides whether ANSI colour should be used for w.
//
// Colour requires: not explicitly disabled, NO_COLOR unset, and w being a
// character device. Redirected or piped output therefore never contains
// escape sequences.
func ColorEnabled(w io.Writer, disabled bool) bool {
	if disabled {
		return false
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// ---------------------------------------------------------------------------
// Attribute helpers
// ---------------------------------------------------------------------------

// Duration renders a duration at millisecond resolution, which is the useful
// granularity for the PBKDF2 stages and keeps log lines short.
func Duration(key string, d time.Duration) slog.Attr {
	return slog.String(key, d.Round(time.Millisecond).String())
}
