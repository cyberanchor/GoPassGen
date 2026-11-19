// Package derive implements the GoPassGen password derivation pipeline.
//
// It is a byte-exact reimplementation of PyPassGen v1.3.5. Every constant in
// this file is part of the compatibility contract: changing any of them
// changes every password the tool has ever produced.
//
//  1. m    = NFKD(mnemonic)
//  2. seed = PBKDF2-HMAC-SHA512(pw = m,    salt = "mnemonic"+passphrase, iter = 2048,    dkLen = 64)
//  3. key  = PBKDF2-HMAC-SHA512(pw = seed, salt = "0",                   iter = 1000000, dkLen = 64)
//  4. blk_i = HMAC-SHA512(key, "PyPassGen\x00" || context || uint32be(i)), i = 0, 1, 2, ...
//  5. password: consume stream bytes; accept b if b < 176; char = Charset[b%88];
//     bytes >= 176 are discarded (rejection sampling, no modulo bias).
//
// Secret material is handled as []byte rather than string so that callers can
// wipe it. See Wipe. PBKDF2 and HMAC live in kdf.go, written so that their
// key-dependent state can be erased and a long derivation can be cancelled.
package derive

import (
	"context"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"runtime"
	"time"

	"golang.org/x/text/unicode/norm"
)

const (
	// BaseCharacters and Symbols concatenate into Charset. The ORDER IS PART
	// OF THE FORMAT: the password is Charset[b%88].
	BaseCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	Symbols        = "!@#$%^&*()_+-=[]{};:,.<>?~"
	Charset        = BaseCharacters + Symbols // 62 + 26 = 88

	// CharsetSize is the alphabet size used for rejection sampling and entropy.
	CharsetSize = len(Charset)

	// RejectionLimit is the largest multiple of CharsetSize below 256.
	// Stream bytes >= RejectionLimit are discarded.
	RejectionLimit = (256 / CharsetSize) * CharsetSize // 176

	// SeedIterations is fixed by BIP-39.
	SeedIterations = 2048
	// KeyIterations mirrors PBKDF2_ITERATIONS in pypassgen.py.
	KeyIterations = 1_000_000
	// KeyLen is the output size of both PBKDF2 stages. Python's
	// hashlib.pbkdf2_hmac defaults dklen to the digest size (64 for SHA-512);
	// Go requires it to be explicit.
	KeyLen = 64

	// MaxPasswordLength mirrors MAX_PASSWORD_LENGTH.
	MaxPasswordLength = 256
	// DefaultPasswordLength mirrors DEFAULT_PASSWORD_LENGTH.
	DefaultPasswordLength = 12
)

var (
	// seedSaltPrefix is the BIP-39 salt prefix: "mnemonic" + passphrase.
	seedSaltPrefix = []byte("mnemonic")
	// fixedSalt is FIXED_SALT = b'0' — the ASCII digit zero (0x30), not 0x00.
	fixedSalt = []byte{'0'}
	// hmacDomain is _HMAC_DOMAIN = b"PyPassGen\x00", trailing NUL included.
	hmacDomain = []byte("PyPassGen\x00")
)

// Errors returned by this package. Callers should match with errors.Is.
var (
	// ErrLengthNotPositive is returned for a password length <= 0.
	ErrLengthNotPositive = errors.New("password length must be positive")
	// ErrLengthTooLarge is returned for a password length above MaxPasswordLength.
	ErrLengthTooLarge = errors.New("password length exceeds maximum")
	// ErrKeyLength is returned when the derivation key has the wrong size.
	ErrKeyLength = errors.New("derivation key must be 64 bytes")
)

// Stats records non-sensitive information about one derivation, for --verbose
// diagnostics. It deliberately contains no secret material.
type Stats struct {
	SeedDuration  time.Duration // stage 2
	KeyDuration   time.Duration // stage 3
	StreamBlocks  int           // HMAC-SHA512 blocks consumed
	BytesConsumed int           // stream bytes examined
	BytesRejected int           // stream bytes discarded by rejection sampling
}

// String renders Stats for a plain text message.
func (s Stats) String() string {
	return fmt.Sprintf(
		"seed=%s key=%s blocks=%d bytes=%d rejected=%d (%.1f%%)",
		s.SeedDuration.Round(time.Millisecond),
		s.KeyDuration.Round(time.Millisecond),
		s.StreamBlocks, s.BytesConsumed, s.BytesRejected,
		s.rejectionRate()*100,
	)
}

// LogValue implements slog.LogValuer, so a caller can log the whole struct as
// one attribute and get a proper group instead of a flattened string:
//
//	log.Debug("derivation complete", "stats", stats)
//
// None of these fields is secret: they are timings, block counts and the
// rejection rate.
func (s Stats) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("seed", s.SeedDuration.Round(time.Millisecond).String()),
		slog.String("key", s.KeyDuration.Round(time.Millisecond).String()),
		slog.Int("blocks", s.StreamBlocks),
		slog.Int("bytes", s.BytesConsumed),
		slog.Int("rejected", s.BytesRejected),
		slog.Float64("rejection_rate", s.rejectionRate()),
	)
}

func (s Stats) rejectionRate() float64 {
	if s.BytesConsumed == 0 {
		return 0
	}
	return float64(s.BytesRejected) / float64(s.BytesConsumed)
}

// NormalizeString applies NFKD, mirroring Mnemonic.normalize_string.
//
// This is load-bearing: Japanese mnemonics are joined with U+3000 (which NFKD
// folds to U+0020) and the French/Spanish wordlists are stored decomposed, so
// precomposed user input must be decomposed before hashing.
func NormalizeString(s string) string {
	return norm.NFKD.String(s)
}

// Seed performs stage 1+2: BIP-39 mnemonic to 64-byte seed.
// The returned slice is secret; wipe it when done.
func Seed(mnemonic, passphrase string) []byte {
	seed, err := SeedContext(context.Background(), mnemonic, passphrase)
	if err != nil {
		panic("derive: a background context was cancelled: " + err.Error())
	}
	return seed
}

// SeedContext is Seed with cancellation.
func SeedContext(ctx context.Context, mnemonic, passphrase string) ([]byte, error) {
	m := TrackSecret([]byte(NormalizeString(mnemonic)))
	p := TrackSecret([]byte(NormalizeString(passphrase)))
	defer Wipe(m)
	defer Wipe(p)

	salt := TrackSecret(make([]byte, len(seedSaltPrefix)+len(p)))
	defer Wipe(salt)
	copy(salt, seedSaltPrefix)
	copy(salt[len(seedSaltPrefix):], p)

	return pbkdf2SHA512(ctx, m, salt, SeedIterations)
}

// Key performs stage 3: seed to 64-byte derivation key.
// This is the expensive step (1,000,000 iterations).
// The returned slice is secret; wipe it when done.
func Key(seed []byte) []byte {
	key, err := KeyContext(context.Background(), seed)
	if err != nil {
		panic("derive: a background context was cancelled: " + err.Error())
	}
	return key
}

// KeyContext is Key with cancellation: it returns ctx.Err() shortly after ctx
// is cancelled instead of finishing all iterations.
func KeyContext(ctx context.Context, seed []byte) ([]byte, error) {
	return pbkdf2SHA512(ctx, seed, fixedSalt, KeyIterations)
}

// Password performs stages 4+5: key to password bytes.
//
// domain is the optional domain-separation input. PyPassGen always passes an
// empty one, so callers that need bit-compatibility must pass nil.
//
// The result is returned as []byte so the caller can wipe it after use;
// converting it to string creates an immutable copy that cannot be erased.
func Password(key []byte, length int, domain []byte) ([]byte, Stats, error) {
	var st Stats

	if len(key) != KeyLen {
		return nil, st, fmt.Errorf("%w: got %d", ErrKeyLength, len(key))
	}
	if length <= 0 {
		return nil, st, fmt.Errorf("%w: %d", ErrLengthNotPositive, length)
	}
	if length > MaxPasswordLength {
		return nil, st, fmt.Errorf("%w: %d > %d", ErrLengthTooLarge, length, MaxPasswordLength)
	}

	out := make([]byte, 0, length)
	msg := make([]byte, 0, len(hmacDomain)+len(domain)+4)
	ctr := make([]byte, 4)
	block := TrackSecret(make([]byte, sha512.Size))
	defer Wipe(block)
	mac := newHMAC(key)
	defer mac.wipe()

	for counter := uint32(0); len(out) < length; counter++ {
		binary.BigEndian.PutUint32(ctr, counter)

		msg = msg[:0]
		msg = append(msg, hmacDomain...)
		msg = append(msg, domain...)
		msg = append(msg, ctr...)

		mac.sum(block, msg, nil)
		st.StreamBlocks++

		for _, b := range block {
			st.BytesConsumed++
			if int(b) >= RejectionLimit {
				st.BytesRejected++
				continue
			}
			out = append(out, Charset[int(b)%CharsetSize])
			if len(out) == length {
				break
			}
		}
	}

	Wipe(msg)
	return out, st, nil
}

// FromMnemonic runs the whole pipeline and wipes every intermediate byte slice.
// It performs no BIP-39 validation — that belongs to package bip39 and is
// enforced by package passgen.
func FromMnemonic(mnemonic, passphrase string, length int, domain []byte) ([]byte, Stats, error) {
	return FromMnemonicContext(context.Background(), mnemonic, passphrase, length, domain)
}

// FromMnemonicContext is FromMnemonic with cancellation.
func FromMnemonicContext(ctx context.Context, mnemonic, passphrase string, length int, domain []byte) ([]byte, Stats, error) {
	if length <= 0 {
		return nil, Stats{}, fmt.Errorf("%w: %d", ErrLengthNotPositive, length)
	}
	if length > MaxPasswordLength {
		return nil, Stats{}, fmt.Errorf("%w: %d > %d", ErrLengthTooLarge, length, MaxPasswordLength)
	}

	t0 := time.Now()
	seed, err := SeedContext(ctx, mnemonic, passphrase)
	if err != nil {
		return nil, Stats{}, err
	}
	defer Wipe(TrackSecret(seed))
	t1 := time.Now()
	key, err := KeyContext(ctx, seed)
	if err != nil {
		return nil, Stats{}, err
	}
	defer Wipe(TrackSecret(key))
	t2 := time.Now()

	pw, st, err := Password(key, length, domain)
	if err != nil {
		return nil, Stats{}, err
	}

	st.SeedDuration = t1.Sub(t0)
	st.KeyDuration = t2.Sub(t1)
	return pw, st, nil
}

// EntropyBits reports the upper bound H = length * log2(88).
//
// It is an upper bound only. The real entropy is capped by the mnemonic
// (128 bits for 12 words, 256 for 24), so a 256-character password derived
// from a 12-word phrase still carries at most 128 bits.
func EntropyBits(length int) float64 {
	if length <= 0 {
		return 0
	}
	return float64(length) * math.Log2(float64(CharsetSize))
}

// EffectiveEntropyBits reports the smaller of the charset bound and the
// mnemonic entropy, which is the number that actually matters.
func EffectiveEntropyBits(length, mnemonicBits int) float64 {
	return math.Min(EntropyBits(length), float64(mnemonicBits))
}

// Wipe overwrites b with zeros.
//
// Best effort, exactly as in the Python original: Go's runtime may have copied
// the data beforehand, and a mnemonic held in a string cannot be erased at all.
// It does reliably clear the slice the caller holds.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
