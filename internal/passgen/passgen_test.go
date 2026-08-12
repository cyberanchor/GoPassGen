package passgen

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"gopassgen/internal/bip39"
	"gopassgen/internal/derive"
	"gopassgen/internal/logx"
)

const (
	validEN = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	// Reference output of PyPassGen 1.3.5 for validEN at length 12.
	validENPassword12 = ",6UiYsb-haPx"
)

func newTestGen(t *testing.T, language string) *Generator {
	t.Helper()
	g, err := New(language, nil)
	if err != nil {
		t.Fatalf("New(%q): %v", language, err)
	}
	return g
}

func TestNew(t *testing.T) {
	for _, lang := range bip39.Languages() {
		g, err := New(lang, nil)
		if err != nil {
			t.Fatalf("New(%q): %v", lang, err)
		}
		if g.Language() != lang {
			t.Errorf("Language() = %q, want %q", g.Language(), lang)
		}
		if g.Wordlist() == nil {
			t.Error("Wordlist() must not be nil")
		}
	}
}

func TestNewUnsupportedLanguage(t *testing.T) {
	if _, err := New("klingon", nil); !errors.Is(err, bip39.ErrUnsupportedLanguage) {
		t.Errorf("error = %v, want ErrUnsupportedLanguage", err)
	}
}

func TestNewWithLoggerEmitsDebug(t *testing.T) {
	var buf bytes.Buffer
	log := logx.New(&buf, logx.Options{Level: slog.LevelDebug})
	if _, err := New("english", log); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "wordlist loaded") {
		t.Errorf("expected a debug line, got %q", out)
	}
	if !strings.Contains(out, "words=2048") {
		t.Errorf("expected a structured attribute, got %q", out)
	}
	// The language belongs to the caller's context: a logger decorated with
	// With must propagate it into this package's records.
	buf.Reset()
	if _, err := New("french", log.With(slog.String("language", "french"))); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "language=french") {
		t.Errorf("caller attributes must propagate, got %q", buf.String())
	}
}

func TestPasswordRejectsInvalidMnemonic(t *testing.T) {
	g := newTestGen(t, "english")
	cases := []struct {
		name     string
		mnemonic string
		inner    error
	}{
		{"bad checksum", strings.Replace(validEN, "about", "abandon", 1), bip39.ErrChecksum},
		{"unknown word", strings.Replace(validEN, "about", "zzzz", 1), bip39.ErrUnknownWord},
		{"too few words", "abandon abandon", bip39.ErrWordCount},
		{"empty", "", bip39.ErrWordCount},
		{"double space", strings.Replace(validEN, "abandon abandon", "abandon  abandon", 1), bip39.ErrWordCount},
		{"trailing space", validEN + " ", bip39.ErrWordCount},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pw, err := g.Password(c.mnemonic, 12)
			if !errors.Is(err, ErrInvalidMnemonic) {
				t.Fatalf("error = %v, want ErrInvalidMnemonic", err)
			}
			if !errors.Is(err, c.inner) {
				t.Errorf("error = %v, want it to wrap %v", err, c.inner)
			}
			if pw != nil {
				t.Errorf("password must be nil on error, got %q", pw)
			}
		})
	}
}

func TestPasswordRejectsBadLength(t *testing.T) {
	g := newTestGen(t, "english")
	for _, n := range []int{0, -1, -256, derive.MaxPasswordLength + 1, 1 << 20} {
		if _, err := g.Password(validEN, n); err == nil {
			t.Errorf("length %d: expected an error", n)
		}
	}
}

func TestPasswordKnownAnswer(t *testing.T) {
	if testing.Short() {
		t.Skip("1,000,000 PBKDF2 iterations")
	}
	g := newTestGen(t, "english")
	pw, err := g.Password(validEN, len(validENPassword12))
	if err != nil {
		t.Fatal(err)
	}
	defer derive.Wipe(pw)
	if string(pw) != validENPassword12 {
		t.Errorf("password = %q, want %q", pw, validENPassword12)
	}
}

func TestPasswordDebugLoggingHidesSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("1,000,000 PBKDF2 iterations")
	}
	var buf bytes.Buffer
	log := logx.New(&buf, logx.Options{Level: slog.LevelDebug})
	g, err := New("english", log)
	if err != nil {
		t.Fatal(err)
	}
	pw, err := g.Password(validEN, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer derive.Wipe(pw)

	out := buf.String()
	// Structured attributes, not a formatted sentence: these are the keys the
	// JSON handler would emit too.
	for _, want := range []string{
		"password derived",
		"stats.blocks=",
		"stats.rejected=",
		"entropy.charset_bits=",
		"entropy.mnemonic_bits=128",
		"entropy.effective_bits=",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("debug output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, string(pw)) {
		t.Error("debug output leaked the password")
	}
	for _, word := range strings.Fields(validEN) {
		if strings.Contains(out, word) {
			t.Fatalf("debug output leaked mnemonic word %q", word)
		}
	}
}

func TestMnemonicAndPair(t *testing.T) {
	if testing.Short() {
		t.Skip("1,000,000 PBKDF2 iterations")
	}
	g := newTestGen(t, "english")

	for _, words := range bip39.WordCounts() {
		m, err := g.Mnemonic(words)
		if err != nil {
			t.Fatalf("Mnemonic(%d): %v", words, err)
		}
		if bip39.WordCount(m) != words {
			t.Errorf("Mnemonic(%d) produced %d words", words, bip39.WordCount(m))
		}
	}
	if _, err := g.Mnemonic(13); !errors.Is(err, bip39.ErrWordCount) {
		t.Errorf("Mnemonic(13) error = %v", err)
	}

	p, err := g.Pair(12, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Password) != 16 {
		t.Errorf("pair password length = %d, want 16", len(p.Password))
	}
	if err := g.Wordlist().Validate(p.Mnemonic); err != nil {
		t.Errorf("pair mnemonic is invalid: %v", err)
	}

	// The pair's password must be reproducible from its own mnemonic.
	again, err := g.Password(p.Mnemonic, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Password, again) {
		t.Errorf("pair is not self-consistent: %q vs %q", p.Password, again)
	}

	p.Wipe()
	for _, b := range p.Password {
		if b != 0 {
			t.Fatal("Wipe did not clear the password")
		}
	}
}

func TestPairBadArguments(t *testing.T) {
	g := newTestGen(t, "english")
	if _, err := g.Pair(13, 16); err == nil {
		t.Error("Pair with 13 words: expected an error")
	}
	if _, err := g.Pair(12, 0); err == nil {
		t.Error("Pair with length 0: expected an error")
	}
	if _, err := g.Pair(12, derive.MaxPasswordLength+1); err == nil {
		t.Error("Pair with oversized length: expected an error")
	}
}

func TestPairsOrderAndUniqueness(t *testing.T) {
	if testing.Short() {
		t.Skip("many PBKDF2 runs")
	}
	g := newTestGen(t, "english")

	const n = 6
	pairs, err := g.Pairs(context.Background(), n, 12, 16, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer wipeAll(pairs)

	if len(pairs) != n {
		t.Fatalf("got %d pairs, want %d", len(pairs), n)
	}
	seen := map[string]bool{}
	for i, p := range pairs {
		if p.Mnemonic == "" || len(p.Password) != 16 {
			t.Fatalf("pair %d is incomplete: %+v", i, p)
		}
		if seen[p.Mnemonic] {
			t.Errorf("pair %d repeats a mnemonic", i)
		}
		seen[p.Mnemonic] = true
	}
}

func TestPairsJobsVariants(t *testing.T) {
	if testing.Short() {
		t.Skip("many PBKDF2 runs")
	}
	g := newTestGen(t, "english")
	for _, jobs := range []int{0, -1, 1, 2, 64} {
		pairs, err := g.Pairs(context.Background(), 3, 12, 12, jobs)
		if err != nil {
			t.Fatalf("jobs=%d: %v", jobs, err)
		}
		if len(pairs) != 3 {
			t.Errorf("jobs=%d: got %d pairs", jobs, len(pairs))
		}
		wipeAll(pairs)
	}
}

func TestPairsRejectsNonPositiveN(t *testing.T) {
	g := newTestGen(t, "english")
	for _, n := range []int{0, -1, -100} {
		if _, err := g.Pairs(context.Background(), n, 12, 12, 1); err == nil {
			t.Errorf("n=%d: expected an error", n)
		}
	}
}

func TestPairsPropagatesBadParameters(t *testing.T) {
	g := newTestGen(t, "english")
	if _, err := g.Pairs(context.Background(), 2, 13, 12, 1); err == nil {
		t.Error("invalid word count must fail the batch")
	}
	if _, err := g.Pairs(context.Background(), 2, 12, -3, 1); err == nil {
		t.Error("invalid password length must fail the batch")
	}
}

func TestPairsCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("PBKDF2 runs")
	}
	g := newTestGen(t, "english")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: the batch must abort without producing output

	_, err := g.Pairs(ctx, 50, 12, 12, 2)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestPairsCancellationMidFlight(t *testing.T) {
	if testing.Short() {
		t.Skip("PBKDF2 runs")
	}
	g := newTestGen(t, "english")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := g.Pairs(ctx, 100, 24, 32, 2)
	if err == nil {
		t.Fatal("expected cancellation")
	}
	// 100 derivations would take far longer than this bound.
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("cancellation took %s, batch did not abort promptly", elapsed)
	}
}

func TestGeneratorIsConcurrencySafe(t *testing.T) {
	g := newTestGen(t, "english")
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := g.Mnemonic(12); err != nil {
				t.Errorf("concurrent Mnemonic: %v", err)
			}
			if err := g.Wordlist().Validate(validEN); err != nil {
				t.Errorf("concurrent Validate: %v", err)
			}
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Self test
// ---------------------------------------------------------------------------

func TestSelfTest(t *testing.T) {
	if testing.Short() {
		t.Skip("1,000,000 PBKDF2 iterations")
	}
	results, err := SelfTest()
	if err != nil {
		t.Fatalf("SelfTest failed: %v", err)
	}
	want := []string{"alphabet", "wordlists", "nfkd", "bip39-seed", "stream", "kdf", "end-to-end"}
	if len(results) != len(want) {
		t.Fatalf("got %d checks, want %d", len(results), len(want))
	}
	for i, name := range want {
		if results[i].Name != name {
			t.Errorf("check %d = %q, want %q", i, results[i].Name, name)
		}
		if !results[i].Passed {
			t.Errorf("check %q failed: %s", results[i].Name, results[i].Detail)
		}
		if results[i].Detail == "" {
			t.Errorf("check %q has no detail", results[i].Name)
		}
	}
}

func TestSelfTestDigestsMatchEmbeddedWordlists(t *testing.T) {
	if len(wordlistDigests) != len(bip39.Languages()) {
		t.Fatalf("digest table covers %d languages, wordlists cover %d",
			len(wordlistDigests), len(bip39.Languages()))
	}
	for _, lang := range bip39.Languages() {
		if _, ok := wordlistDigests[lang]; !ok {
			t.Errorf("no digest recorded for %q", lang)
		}
	}
}

func BenchmarkPassword(b *testing.B) {
	g, err := New("english", nil)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		pw, err := g.Password(validEN, 16)
		if err != nil {
			b.Fatal(err)
		}
		derive.Wipe(pw)
	}
}
