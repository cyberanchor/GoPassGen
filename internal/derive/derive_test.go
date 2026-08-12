package derive

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Alphabet and constants
// ---------------------------------------------------------------------------

func TestCharsetInvariants(t *testing.T) {
	if got := len(Charset); got != 88 {
		t.Fatalf("charset size = %d, want 88", got)
	}
	if len(BaseCharacters) != 62 {
		t.Errorf("base characters = %d, want 62", len(BaseCharacters))
	}
	if len(Symbols) != 26 {
		t.Errorf("symbols = %d, want 26", len(Symbols))
	}
	if CharsetSize != len(Charset) {
		t.Errorf("CharsetSize = %d, want %d", CharsetSize, len(Charset))
	}
	if RejectionLimit != 176 {
		t.Errorf("RejectionLimit = %d, want 176", RejectionLimit)
	}
	if RejectionLimit%CharsetSize != 0 {
		t.Errorf("RejectionLimit %d is not a multiple of %d — sampling would be biased",
			RejectionLimit, CharsetSize)
	}
	if RejectionLimit+CharsetSize <= 256 {
		t.Errorf("RejectionLimit %d is not the LARGEST multiple of %d below 256",
			RejectionLimit, CharsetSize)
	}
	if !utf8.ValidString(Charset) {
		t.Error("charset must be valid UTF-8")
	}

	seen := map[byte]int{}
	for i := 0; i < len(Charset); i++ {
		seen[Charset[i]]++
	}
	if len(seen) != len(Charset) {
		t.Errorf("charset has duplicate characters: %d unique of %d", len(seen), len(Charset))
	}
	for i := 0; i < len(Charset); i++ {
		if c := Charset[i]; c < 0x21 || c > 0x7E {
			t.Errorf("charset[%d] = %q is outside printable ASCII", i, c)
		}
	}
}

func TestCharsetExactContent(t *testing.T) {
	// Frozen: the order defines every password ever produced.
	const want = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
		"!@#$%^&*()_+-=[]{};:,.<>?~"
	if Charset != want {
		t.Fatalf("charset changed — this breaks compatibility with every existing password\ngot:  %q\nwant: %q", Charset, want)
	}
}

func TestParameterConstants(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"SeedIterations", SeedIterations, 2048},
		{"KeyIterations", KeyIterations, 1000000},
		{"KeyLen", KeyLen, 64},
		{"MaxPasswordLength", MaxPasswordLength, 256},
		{"DefaultPasswordLength", DefaultPasswordLength, 12},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if !bytes.Equal(fixedSalt, []byte{0x30}) {
		t.Errorf("fixed salt = %x, want 30 (ASCII '0', not NUL)", fixedSalt)
	}
	if !bytes.Equal(hmacDomain, []byte("PyPassGen\x00")) {
		t.Errorf("hmac domain = %q, want %q", hmacDomain, "PyPassGen\x00")
	}
	if !bytes.Equal(seedSaltPrefix, []byte("mnemonic")) {
		t.Errorf("seed salt prefix = %q, want %q", seedSaltPrefix, "mnemonic")
	}
}

// ---------------------------------------------------------------------------
// NFKD normalization
// ---------------------------------------------------------------------------

func TestNormalizeString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain ascii unchanged", "abandon about", "abandon about"},
		{"ideographic space folds", "a\u3000b", "a b"},
		{"precomposed decomposes", "d\u00e9cider", "de\u0301cider"},
		{"already decomposed stable", "de\u0301cider", "de\u0301cider"},
		{"empty", "", ""},
		{"halfwidth katakana expands", "\uff76", "\u30ab"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NormalizeString(c.in); got != c.want {
				t.Errorf("NormalizeString(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestNormalizeIsIdempotent(t *testing.T) {
	for _, s := range []string{"d\u00e9cider", "a\u3000b", "\uff76\uff9e", "abandon"} {
		once := NormalizeString(s)
		if twice := NormalizeString(once); twice != once {
			t.Errorf("NFKD not idempotent for %q: %q vs %q", s, once, twice)
		}
	}
}

// ---------------------------------------------------------------------------
// Seed stage
// ---------------------------------------------------------------------------

func TestSeedKnownVectors(t *testing.T) {
	// Reference values produced by python-mnemonic (the library PyPassGen uses)
	// with an empty passphrase, which is the only mode GoPassGen exercises.
	cases := []struct {
		mnemonic string
		want     string
	}{
		{
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1" +
				"9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
		},
		{
			"legal winner thank year wave sausage worth useful legal winner thank yellow",
			"878386efb78845b3355bd15ea4d39ef97d179cb712b77d5c12b6be415fffeffe" +
				"5f377ba02bf3f8544ab800b955e51fbff09828f682052a20faa6addbbddfb096",
		},
		{
			"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
			"b6a6d8921942dd9806607ebc2750416b289adea669198769f2e15ed926c3aa92" +
				"bf88ece232317b4ea463e84b0fcd3b53577812ee449ccc448eb45e6f544e25b6",
		},
	}
	for _, c := range cases {
		got := hex.EncodeToString(Seed(c.mnemonic, ""))
		if got != c.want {
			t.Errorf("Seed(%.20s...) =\n %s\nwant\n %s", c.mnemonic, got, c.want)
		}
	}
}

func TestSeedWithPassphraseDiffers(t *testing.T) {
	const m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	a := Seed(m, "")
	b := Seed(m, "TREZOR")
	if bytes.Equal(a, b) {
		t.Fatal("passphrase must change the seed")
	}
	// Official BIP-39 test vector (passphrase "TREZOR"). GoPassGen always uses
	// the empty passphrase, so this only guards the plumbing.
	want := "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553" +
		"1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
	if got := hex.EncodeToString(b); got != want {
		t.Errorf("Seed with TREZOR passphrase = %s, want %s", got, want)
	}
}

func TestSeedLength(t *testing.T) {
	if got := len(Seed("abandon about", "")); got != KeyLen {
		t.Errorf("seed length = %d, want %d", got, KeyLen)
	}
}

func TestSeedNormalizesInput(t *testing.T) {
	// Precomposed and decomposed spellings must hash to the same seed.
	a := Seed("d\u00e9cider abandon", "")
	b := Seed("de\u0301cider abandon", "")
	if !bytes.Equal(a, b) {
		t.Error("NFKD normalization is not applied to the mnemonic")
	}
	// Ideographic and plain spaces likewise.
	c := Seed("abandon\u3000about", "")
	d := Seed("abandon about", "")
	if !bytes.Equal(c, d) {
		t.Error("NFKD normalization does not fold U+3000")
	}
}

// ---------------------------------------------------------------------------
// Key stage
// ---------------------------------------------------------------------------

func TestKeyKnownVector(t *testing.T) {
	if testing.Short() {
		t.Skip("1,000,000 PBKDF2 iterations")
	}
	seed, err := hex.DecodeString(
		"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1" +
			"9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
	if err != nil {
		t.Fatal(err)
	}
	want := "d2f55c9e3ba067d7f3b514dd3cb1fe9519ad825fadfb2303a89f17a70ba4862f" +
		"e9d877c529390dcf82871536246114f5b5c46c249198a75b4cba9ad1d3875eec"
	if got := hex.EncodeToString(Key(seed)); got != want {
		t.Errorf("Key = %s, want %s", got, want)
	}
}

// ---------------------------------------------------------------------------
// Password stage
// ---------------------------------------------------------------------------

func zeroKey() []byte { return make([]byte, KeyLen) }

func TestPasswordKnownVectors(t *testing.T) {
	ff := bytes.Repeat([]byte{0xFF}, KeyLen)
	cases := []struct {
		name   string
		key    []byte
		length int
		want   string
	}{
		{"zero key, 32", zeroKey(), 32, "rUMG$O7plxu8}U~.]:_}sG+HZ(r&#tpO"},
		{"0xFF key, 16", ff, 16, "G>WkaOaH]$LQi4@q"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _, err := Password(c.key, c.length, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestPasswordLengthBoundaries(t *testing.T) {
	key := zeroKey()
	for _, n := range []int{1, 2, 63, 64, 65, 88, 127, 128, 176, 255, MaxPasswordLength} {
		got, _, err := Password(key, n, nil)
		if err != nil {
			t.Fatalf("length %d: unexpected error: %v", n, err)
		}
		if len(got) != n {
			t.Errorf("length %d: got %d bytes", n, len(got))
		}
		for i, b := range got {
			if !strings.ContainsRune(Charset, rune(b)) {
				t.Fatalf("length %d: byte %d = %q is outside the charset", n, i, b)
			}
		}
	}
}

func TestPasswordRejectsBadArguments(t *testing.T) {
	key := zeroKey()
	cases := []struct {
		name    string
		key     []byte
		length  int
		wantErr error
	}{
		{"zero length", key, 0, ErrLengthNotPositive},
		{"negative length", key, -1, ErrLengthNotPositive},
		{"large negative length", key, -1 << 30, ErrLengthNotPositive},
		{"length above max", key, MaxPasswordLength + 1, ErrLengthTooLarge},
		{"huge length", key, 1 << 20, ErrLengthTooLarge},
		{"nil key", nil, 12, ErrKeyLength},
		{"short key", make([]byte, 32), 12, ErrKeyLength},
		{"long key", make([]byte, 65), 12, ErrKeyLength},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _, err := Password(c.key, c.length, nil)
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("error = %v, want %v", err, c.wantErr)
			}
			if got != nil {
				t.Errorf("password must be nil on error, got %q", got)
			}
		})
	}
}

func TestPasswordIsDeterministic(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, KeyLen)
	first, _, err := Password(key, 64, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		again, _, err := Password(key, 64, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("run %d differs: %q vs %q", i, first, again)
		}
	}
}

func TestPasswordIsPrefixStable(t *testing.T) {
	// Documented property of the format: a shorter password is a prefix of a
	// longer one derived from the same key. Asserted so it cannot change
	// silently — not endorsed as a good design (see README).
	key := bytes.Repeat([]byte{0x11}, KeyLen)
	long, _, err := Password(key, MaxPasswordLength, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{1, 12, 16, 32, 64, 100, 255} {
		short, _, err := Password(key, n, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(long, short) {
			t.Errorf("length %d is not a prefix of the %d-char password", n, MaxPasswordLength)
		}
	}
}

func TestPasswordContextSeparation(t *testing.T) {
	key := zeroKey()
	base, _, err := Password(key, 32, nil)
	if err != nil {
		t.Fatal(err)
	}
	empty, _, err := Password(key, 32, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(base, empty) {
		t.Error("nil and empty context must be equivalent (PyPassGen passes b\"\")")
	}
	other, _, err := Password(key, 32, []byte("site:example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(base, other) {
		t.Error("a non-empty context must change the output")
	}
}

func TestPasswordKeySensitivity(t *testing.T) {
	// Flipping a single bit of the key must change the password.
	base := zeroKey()
	first, _, err := Password(base, 32, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, bit := range []int{0, 7, 255, 511} {
		k := zeroKey()
		k[bit/8] ^= 1 << uint(bit%8)
		got, _, err := Password(k, 32, nil)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(first, got) {
			t.Errorf("flipping key bit %d did not change the password", bit)
		}
	}
}

func TestPasswordStats(t *testing.T) {
	key := zeroKey()
	_, st, err := Password(key, 200, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.StreamBlocks < 4 {
		t.Errorf("200 chars need at least 4 blocks of 64 bytes, got %d", st.StreamBlocks)
	}
	if st.BytesConsumed < 200 {
		t.Errorf("bytes consumed = %d, want >= 200", st.BytesConsumed)
	}
	if st.BytesRejected < 0 || st.BytesRejected > st.BytesConsumed {
		t.Errorf("rejected = %d out of %d consumed", st.BytesRejected, st.BytesConsumed)
	}
	if s := st.String(); !strings.Contains(s, "blocks=") || !strings.Contains(s, "rejected=") {
		t.Errorf("Stats.String() = %q, missing fields", s)
	}
	var empty Stats
	if got := empty.rejectionRate(); got != 0 {
		t.Errorf("rejection rate of empty stats = %v, want 0", got)
	}
}

// TestStatsLogValue checks the slog.LogValuer implementation: logging the
// struct as one attribute must produce a group of typed fields, not a
// flattened string, and must expose nothing secret.
func TestStatsLogValue(t *testing.T) {
	st := Stats{
		SeedDuration:  1500 * time.Microsecond,
		KeyDuration:   700 * time.Millisecond,
		StreamBlocks:  4,
		BytesConsumed: 256,
		BytesRejected: 32,
	}

	v := st.LogValue()
	if v.Kind() != slog.KindGroup {
		t.Fatalf("LogValue kind = %v, want a group", v.Kind())
	}

	got := map[string]slog.Value{}
	for _, a := range v.Group() {
		got[a.Key] = a.Value
	}
	for _, key := range []string{"seed", "key", "blocks", "bytes", "rejected", "rejection_rate"} {
		if _, ok := got[key]; !ok {
			t.Errorf("group is missing %q", key)
		}
	}
	if got["blocks"].Int64() != 4 {
		t.Errorf("blocks = %v, want 4", got["blocks"])
	}
	if got["bytes"].Int64() != 256 {
		t.Errorf("bytes = %v, want 256", got["bytes"])
	}
	if rate := got["rejection_rate"].Float64(); rate != 0.125 {
		t.Errorf("rejection_rate = %v, want 0.125", rate)
	}
	if s := got["key"].String(); s != "700ms" {
		t.Errorf("key duration = %q, want 700ms", s)
	}
	// Durations are rounded to milliseconds, so 1.5ms becomes 2ms.
	if s := got["seed"].String(); s != "2ms" {
		t.Errorf("seed duration = %q, want 2ms", s)
	}

	// Whatever is logged must contain no key material: the struct simply has
	// no field that could hold any.
	if n := len(v.Group()); n != 6 {
		t.Errorf("group has %d fields, want exactly 6", n)
	}
}

// TestRejectionSamplingIsUnbiased checks that no character is systematically
// favoured. With a rejection limit of 176 = 2*88 each accepted byte maps to a
// character with equal probability, so a large sample must be roughly flat.
func TestRejectionSamplingIsUnbiased(t *testing.T) {
	if testing.Short() {
		t.Skip("statistical test")
	}
	counts := make(map[byte]int, CharsetSize)
	const perKey = MaxPasswordLength
	const keys = 400
	for i := 0; i < keys; i++ {
		key := make([]byte, KeyLen)
		key[0] = byte(i)
		key[1] = byte(i >> 8)
		pw, _, err := Password(key, perKey, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range pw {
			counts[b]++
		}
	}
	total := keys * perKey
	expected := float64(total) / float64(CharsetSize)
	if len(counts) != CharsetSize {
		t.Errorf("only %d of %d characters ever appeared", len(counts), CharsetSize)
	}
	// Chi-square with 87 degrees of freedom: the 99.9% critical value is
	// about 140. A biased mapping (e.g. plain modulo without rejection)
	// blows far past this.
	chi := 0.0
	for i := 0; i < len(Charset); i++ {
		d := float64(counts[Charset[i]]) - expected
		chi += d * d / expected
	}
	if chi > 160 {
		t.Errorf("chi-square = %.1f over %d samples: distribution looks biased", chi, total)
	}
}

// ---------------------------------------------------------------------------
// FromMnemonic
// ---------------------------------------------------------------------------

func TestFromMnemonicRejectsBadLength(t *testing.T) {
	for _, n := range []int{0, -1, MaxPasswordLength + 1} {
		if _, _, err := FromMnemonic("abandon about", "", n, nil); err == nil {
			t.Errorf("length %d: expected an error", n)
		}
	}
}

func TestFromMnemonicMatchesStages(t *testing.T) {
	if testing.Short() {
		t.Skip("1,000,000 PBKDF2 iterations")
	}
	const m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	seed := Seed(m, "")
	key := Key(seed)
	want, _, err := Password(key, 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, st, err := FromMnemonic(m, "", 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("FromMnemonic = %q, staged = %q", got, want)
	}
	if st.SeedDuration <= 0 || st.KeyDuration <= 0 {
		t.Errorf("stats must record stage timings, got %s", st)
	}
}

// ---------------------------------------------------------------------------
// Entropy helpers and Wipe
// ---------------------------------------------------------------------------

func TestEntropyBits(t *testing.T) {
	cases := []struct {
		length int
		want   float64
	}{{0, 0}, {-5, 0}, {1, 6.4594}, {12, 77.5}, {16, 103.4}, {32, 206.7}, {256, 1653.6}}
	for _, c := range cases {
		got := EntropyBits(c.length)
		if diff := got - c.want; diff > 0.1 || diff < -0.1 {
			t.Errorf("EntropyBits(%d) = %.4f, want ~%.4f", c.length, got, c.want)
		}
	}
}

func TestEffectiveEntropyBits(t *testing.T) {
	// A 256-char password from a 12-word phrase is still capped at 128 bits.
	if got := EffectiveEntropyBits(256, 128); got != 128 {
		t.Errorf("EffectiveEntropyBits(256, 128) = %v, want 128", got)
	}
	// A 12-char password is charset-limited even with a 24-word phrase.
	if got := EffectiveEntropyBits(12, 256); got >= 78 || got <= 77 {
		t.Errorf("EffectiveEntropyBits(12, 256) = %v, want ~77.5", got)
	}
}

func TestWipe(t *testing.T) {
	b := bytes.Repeat([]byte{0xAB}, 64)
	Wipe(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d = %#x after Wipe", i, v)
		}
	}
	Wipe(nil)      // must not panic
	Wipe([]byte{}) // must not panic
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkSeed(b *testing.B) {
	const m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	for i := 0; i < b.N; i++ {
		Wipe(Seed(m, ""))
	}
}

func BenchmarkKey(b *testing.B) {
	seed := make([]byte, KeyLen)
	for i := 0; i < b.N; i++ {
		Wipe(Key(seed))
	}
}

func BenchmarkPassword(b *testing.B) {
	key := make([]byte, KeyLen)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pw, _, err := Password(key, 32, nil)
		if err != nil {
			b.Fatal(err)
		}
		Wipe(pw)
	}
}

func ExamplePassword() {
	key := make([]byte, KeyLen) // all-zero key, for illustration only
	pw, _, err := Password(key, 12, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pw))
	// Output: rUMG$O7plxu8
}
