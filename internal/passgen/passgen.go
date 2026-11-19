// Package passgen ties BIP-39 validation to the derivation pipeline and
// provides the batch and self-test operations used by the CLI.
package passgen

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"

	"github.com/cyberanchor/GoPassGen/internal/bip39"
	"github.com/cyberanchor/GoPassGen/internal/derive"
	"github.com/cyberanchor/GoPassGen/internal/logx"
)

// ErrInvalidMnemonic wraps every rejection coming from BIP-39 validation, so
// callers can branch on one sentinel while still unwrapping the detail.
var ErrInvalidMnemonic = errors.New("invalid mnemonic")

// Pair is a generated mnemonic together with its password.
type Pair struct {
	Mnemonic string
	Password []byte
}

// Wipe erases the password bytes. The mnemonic is an immutable string and
// cannot be erased; treat the whole Pair as short-lived.
func (p *Pair) Wipe() {
	derive.Wipe(p.Password)
}

// Generator produces mnemonics and passwords for one language.
// It is safe for concurrent use.
type Generator struct {
	wl  *bip39.Wordlist
	log *slog.Logger

	// pair produces one batch item. Tests replace it to observe ordering and
	// failure handling, which random phrases would otherwise hide.
	pair func(ctx context.Context, words, length int) (Pair, error)
}

// New builds a Generator for the given language.
// log may be nil, in which case diagnostics are discarded.
func New(language string, log *slog.Logger) (*Generator, error) {
	wl, err := bip39.Load(language)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = logx.Discard()
	}
	// The language is the caller's context, not this package's: whoever builds
	// the logger decorates it once with slog.Logger.With, and every record
	// inherits it. Adding it here as well would duplicate the attribute.
	log.Debug("wordlist loaded", slog.Int("words", bip39.WordlistSize))
	g := &Generator{wl: wl, log: log}
	g.pair = g.PairContext
	return g, nil
}

// Language returns the configured language.
func (g *Generator) Language() string { return g.wl.Language() }

// Wordlist exposes the underlying wordlist for callers that need validation
// without derivation.
func (g *Generator) Wordlist() *bip39.Wordlist { return g.wl }

// Password validates a mnemonic and derives its password.
//
// The password is returned as []byte so the caller can wipe it. Every
// intermediate byte slice is wiped before returning; the mnemonic itself is a
// string and cannot be.
func (g *Generator) Password(mnemonic string, length int) ([]byte, error) {
	return g.PasswordContext(context.Background(), mnemonic, length)
}

// PasswordContext is Password with cancellation.
func (g *Generator) PasswordContext(ctx context.Context, mnemonic string, length int) ([]byte, error) {
	if err := g.wl.Validate(mnemonic); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMnemonic, err)
	}

	pw, stats, err := derive.FromMnemonicContext(ctx, mnemonic, "", length, nil)
	if err != nil {
		return nil, err
	}

	// Enabled guards the attribute construction, not just the output: the
	// entropy figures below cost a few floating point operations that are
	// pointless at info level.
	if g.log.Enabled(context.Background(), slog.LevelDebug) {
		bits := bip39.MnemonicBits(mnemonic)
		g.log.Debug("password derived",
			slog.Int("length", length),
			slog.Any("stats", stats),
			slog.Group("entropy",
				slog.Float64("charset_bits", derive.EntropyBits(length)),
				slog.Int("mnemonic_bits", bits),
				slog.Float64("effective_bits", derive.EffectiveEntropyBits(length, bits)),
			),
		)
	}
	return pw, nil
}

// Mnemonic generates a fresh mnemonic phrase.
func (g *Generator) Mnemonic(words int) (string, error) {
	return g.wl.Generate(words)
}

// Pair generates a mnemonic and its password in one step.
func (g *Generator) Pair(words, length int) (Pair, error) {
	return g.PairContext(context.Background(), words, length)
}

// PairContext is Pair with cancellation.
func (g *Generator) PairContext(ctx context.Context, words, length int) (Pair, error) {
	m, err := g.Mnemonic(words)
	if err != nil {
		return Pair{}, err
	}
	pw, err := g.PasswordContext(ctx, m, length)
	if err != nil {
		return Pair{}, err
	}
	return Pair{Mnemonic: m, Password: pw}, nil
}

// Pairs generates n pairs concurrently, preserving order.
//
// jobs bounds the number of parallel derivations; jobs <= 0 means GOMAXPROCS.
// Cancelling the context stops running derivations as well, so Ctrl-C ends a
// batch almost immediately.
func (g *Generator) Pairs(ctx context.Context, n, words, length, jobs int) ([]Pair, error) {
	if n <= 0 {
		return nil, fmt.Errorf("number of phrases must be positive, got %d", n)
	}
	if jobs <= 0 {
		jobs = runtime.GOMAXPROCS(0)
	}
	if jobs > n {
		jobs = n
	}
	g.log.Debug("batch starting",
		slog.Int("pairs", n),
		slog.Int("words", words),
		slog.Int("length", length),
		slog.Int("jobs", jobs),
	)

	out := make([]Pair, n)
	tasks := make(chan int)

	// abort is closed as soon as any worker fails. Without it the feeder can
	// block forever on an unbuffered send once every worker has exited, which
	// is a deadlock, not a slow batch.
	abort := make(chan struct{})

	var (
		wg       sync.WaitGroup
		errOnce  sync.Once
		firstErr error
	)

	fail := func(err error) {
		errOnce.Do(func() {
			firstErr = err
			close(abort)
		})
	}

	worker := func() {
		defer wg.Done()
		for i := range tasks {
			select {
			case <-ctx.Done():
				return
			case <-abort:
				return
			default:
			}
			p, err := g.pair(ctx, words, length)
			if err != nil {
				fail(err)
				return
			}
			out[i] = p
		}
	}

	wg.Add(jobs)
	for i := 0; i < jobs; i++ {
		go worker()
	}

feed:
	for i := 0; i < n; i++ {
		select {
		case tasks <- i:
		case <-ctx.Done():
			break feed
		case <-abort:
			break feed
		}
	}
	close(tasks)
	wg.Wait()

	// Cancellation wins: a worker interrupted mid-derivation reports it as its
	// own failure, and the caller must still see a plain interruption.
	if err := ctx.Err(); err != nil {
		wipeAll(out)
		return nil, err
	}
	if firstErr != nil {
		wipeAll(out)
		return nil, firstErr
	}
	return out, nil
}

func wipeAll(pairs []Pair) {
	for i := range pairs {
		pairs[i].Wipe()
	}
}

// ---------------------------------------------------------------------------
// Known-answer self test
// ---------------------------------------------------------------------------

// Known-answer vectors. These are outputs of the reference implementation
// (PyPassGen 1.3.5 / python-mnemonic) and must never be edited to make a
// failing build pass — a mismatch means the build is broken, not the vector.
// katPasswordZeroKey is a variable only so a test can prove that a failing
// check is reported.
var katPasswordZeroKey = "rUMG$O7plxu8}U~.]:_}sG+HZ(r&#tpO"

const (
	katMnemonicEN = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	katSeedEN     = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1" +
		"9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	katKeyEN = "d2f55c9e3ba067d7f3b514dd3cb1fe9519ad825fadfb2303a89f17a70ba4862f" +
		"e9d877c529390dcf82871536246114f5b5c46c249198a75b4cba9ad1d3875eec"
	katPasswordEN = ",6UiYsb-haPx"

	// Password derived from an all-0xFF key. The all-zero key above and this
	// one exercise stages 4-5 alone, without paying for 1,000,000 iterations.
	katPasswordFFKey = "G>WkaOaH]$LQi4@q"

	// Japanese phrase joined with U+3000; NFKD must fold it to plain spaces.
	katMnemonicJA = "なにごと\u3000せいじ\u3000いほう\u3000うせつ\u3000せきらんうん\u3000あらいぐま" +
		"\u3000りよう\u3000だんあつ\u3000ちあん\u3000いれる\u3000ぬんちゃく\u3000そっけつ"
	katMnemonicJAPlain = "なにごと せいじ いほう うせつ せきらんうん あらいぐま " +
		"りよう だんあつ ちあん いれる ぬんちゃく そっけつ"
)

// SelfTestResult is one named check.
type SelfTestResult struct {
	Name   string
	Passed bool
	Detail string
}

// SelfTest runs the built-in known-answer tests and returns one result per
// check plus an aggregate error if any of them failed.
//
// It verifies, in order: the alphabet, the embedded wordlists, NFKD
// normalization, the BIP-39 seed stage, the stream/rejection stage, and one
// full end-to-end derivation. Only the last check pays for the 1,000,000
// PBKDF2 iterations, so the whole run costs roughly one password.
func SelfTest() ([]SelfTestResult, error) {
	return SelfTestContext(context.Background())
}

// SelfTestContext is SelfTest with cancellation. When ctx is cancelled it
// returns ctx.Err() and no results.
func SelfTestContext(ctx context.Context) ([]SelfTestResult, error) {
	var results []SelfTestResult

	add := func(name string, ok bool, detail string) {
		results = append(results, SelfTestResult{Name: name, Passed: ok, Detail: detail})
	}

	// 1. Alphabet integrity.
	seen := map[byte]bool{}
	dupes := 0
	for i := 0; i < len(derive.Charset); i++ {
		if seen[derive.Charset[i]] {
			dupes++
		}
		seen[derive.Charset[i]] = true
	}
	alphabetOK := len(derive.Charset) == 88 && dupes == 0 && derive.RejectionLimit == 176
	add("alphabet", alphabetOK, fmt.Sprintf("size=%d duplicates=%d rejection-limit=%d",
		len(derive.Charset), dupes, derive.RejectionLimit))

	// 2. Embedded wordlists. Load verifies each SHA-256 digest.
	wordlistOK := true
	detail := ""
	for _, lang := range bip39.Languages() {
		wl, err := bip39.Load(lang)
		if err != nil {
			wordlistOK = false
			detail = err.Error()
			break
		}
		if _, ok := wl.Word(0); !ok {
			wordlistOK = false
			detail = lang + " is empty"
			break
		}
	}
	if wordlistOK {
		detail = fmt.Sprintf("%d wordlists verified against SHA-256 digests", len(bip39.Languages()))
	}
	add("wordlists", wordlistOK, detail)

	// 3. NFKD normalization (U+3000 must fold to U+0020).
	nfkdOK := derive.NormalizeString(katMnemonicJA) == derive.NormalizeString(katMnemonicJAPlain)
	add("nfkd", nfkdOK, "ideographic space folds to U+0020")

	// 4. BIP-39 seed stage (2048 iterations).
	seed, err := derive.SeedContext(ctx, katMnemonicEN, "")
	if err != nil {
		return nil, err
	}
	defer derive.Wipe(seed)
	seedOK := hex.EncodeToString(seed) == katSeedEN
	add("bip39-seed", seedOK, "PBKDF2-HMAC-SHA512 2048 iterations")

	// 5. Stream and rejection sampling, without the expensive stage.
	streamOK := true
	if pw, _, err := derive.Password(make([]byte, derive.KeyLen), 32, nil); err != nil ||
		string(pw) != katPasswordZeroKey {
		streamOK = false
	}
	ffKey := make([]byte, derive.KeyLen)
	for i := range ffKey {
		ffKey[i] = 0xFF
	}
	if pw, _, err := derive.Password(ffKey, 16, nil); err != nil || string(pw) != katPasswordFFKey {
		streamOK = false
	}
	add("stream", streamOK, "HMAC-SHA512 stream + rejection sampling")

	// 6. Full pipeline (1,000,000 iterations).
	key, err := derive.KeyContext(ctx, seed)
	if err != nil {
		return nil, err
	}
	defer derive.Wipe(key)
	keyOK := hex.EncodeToString(key) == katKeyEN
	add("kdf", keyOK, "PBKDF2-HMAC-SHA512 1000000 iterations")

	pw, _, err := derive.Password(key, len(katPasswordEN), nil)
	endToEndOK := err == nil && string(pw) == katPasswordEN
	add("end-to-end", endToEndOK, "mnemonic to password, PyPassGen 1.3.5 vector")

	derive.Wipe(pw)
	derive.Wipe(ffKey)

	var failed []string
	for _, r := range results {
		if !r.Passed {
			failed = append(failed, r.Name)
		}
	}
	if len(failed) > 0 {
		return results, fmt.Errorf("self-test failed: %v", failed)
	}
	return results, nil
}
