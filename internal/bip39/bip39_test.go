package bip39

import (
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"gopassgen/internal/derive"
)

const validEN = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestLanguages(t *testing.T) {
	got := Languages()
	want := []string{"chinese_simplified", "english", "french", "italian", "japanese", "korean", "spanish"}
	if len(got) != len(want) {
		t.Fatalf("Languages() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Languages() = %v, want %v (sorted)", got, want)
		}
	}
	// The returned slice must be a copy: mutating it must not corrupt state.
	got[0] = "tampered"
	if Languages()[0] == "tampered" {
		t.Error("Languages() exposes its backing array")
	}
}

func TestIsSupported(t *testing.T) {
	for _, l := range Languages() {
		if !IsSupported(l) {
			t.Errorf("IsSupported(%q) = false", l)
		}
	}
	for _, l := range []string{"", "russian", "portuguese", "czech", "turkish",
		"chinese_traditional", "English", " english", "english "} {
		if IsSupported(l) {
			t.Errorf("IsSupported(%q) = true, want false", l)
		}
	}
}

func TestWordCountsAndStrength(t *testing.T) {
	want := map[int]int{12: 128, 15: 160, 18: 192, 21: 224, 24: 256}
	counts := WordCounts()
	if len(counts) != len(want) {
		t.Fatalf("WordCounts() = %v", counts)
	}
	for i := 1; i < len(counts); i++ {
		if counts[i-1] >= counts[i] {
			t.Fatalf("WordCounts() not sorted: %v", counts)
		}
	}
	for words, bits := range want {
		got, ok := StrengthBits(words)
		if !ok || got != bits {
			t.Errorf("StrengthBits(%d) = (%d, %v), want (%d, true)", words, got, ok, bits)
		}
	}
	for _, bad := range []int{0, -12, 1, 11, 13, 23, 25, 48} {
		if _, ok := StrengthBits(bad); ok {
			t.Errorf("StrengthBits(%d) reported valid", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

func TestLoadAllLanguages(t *testing.T) {
	for _, lang := range Languages() {
		wl, err := Load(lang)
		if err != nil {
			t.Fatalf("Load(%q): %v", lang, err)
		}
		if wl.Language() != lang {
			t.Errorf("Language() = %q, want %q", wl.Language(), lang)
		}

		wantDelim := " "
		if lang == "japanese" {
			wantDelim = IdeographicSpace
		}
		if wl.Delimiter() != wantDelim {
			t.Errorf("%s: delimiter = %q, want %q", lang, wl.Delimiter(), wantDelim)
		}

		seen := make(map[string]bool, WordlistSize)
		for i := 0; i < WordlistSize; i++ {
			w, ok := wl.Word(i)
			if !ok {
				t.Fatalf("%s: Word(%d) missing", lang, i)
			}
			if w == "" || strings.ContainsAny(w, " \t\r\n") {
				t.Fatalf("%s: word %d = %q has whitespace", lang, i, w)
			}
			if !utf8.ValidString(w) {
				t.Fatalf("%s: word %d is not valid UTF-8", lang, i)
			}
			if seen[w] {
				t.Fatalf("%s: duplicate word %d", lang, i)
			}
			seen[w] = true

			if idx, ok := wl.Index(w); !ok || idx != i {
				t.Fatalf("%s: Index round-trip failed at %d", lang, i)
			}
		}
	}
}

func TestLoadUnsupported(t *testing.T) {
	for _, lang := range []string{"", "klingon", "russian", "ENGLISH"} {
		_, err := Load(lang)
		if !errors.Is(err, ErrUnsupportedLanguage) {
			t.Errorf("Load(%q) error = %v, want ErrUnsupportedLanguage", lang, err)
		}
	}
}

func TestLoadIsCachedAndConcurrent(t *testing.T) {
	a, err := Load("english")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load("english")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("Load should return the cached instance")
	}

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lang := Languages()[i%len(Languages())]
			wl, err := Load(lang)
			if err != nil {
				t.Errorf("concurrent Load(%s): %v", lang, err)
				return
			}
			if !wl.IsValid(validEN) && lang == "english" {
				t.Error("concurrent validation failed")
			}
		}(i)
	}
	wg.Wait()
}

func TestWordOutOfRange(t *testing.T) {
	wl, err := Load("english")
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{-1, WordlistSize, WordlistSize + 1, 1 << 20} {
		if w, ok := wl.Word(i); ok {
			t.Errorf("Word(%d) = %q, want not ok", i, w)
		}
	}
	if _, ok := wl.Index("definitely-not-a-word"); ok {
		t.Error("Index reported an unknown word as present")
	}
}

func TestDigests(t *testing.T) {
	// SHA-256 of the wordlist files published with BIP-39.
	want := map[string]string{
		"english":            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
		"french":             "ebc3959ab7801a1df6bac4fa7d970652f1df76b683cd2f4003c941c63d517e59",
		"spanish":            "46846a5a0139d1e3cb77293e521c2865f7bcdb82c44e8d0a06a2cd0ecba48c0b",
		"italian":            "d392c49fdb700a24cd1fceb237c1f65dcc128f6b34a8aacb58b59384b5c648c2",
		"japanese":           "2eed0aef492291e061633d7ad8117f1a2b03eb80a29d0e4e3117ac2528d05ffd",
		"korean":             "9e95f86c167de88f450f0aaf89e87f6624a57f973c67b516e338e8e8b8897f60",
		"chinese_simplified": "5c5942792bd8340cb8b27cd592f1015edf56a8c5b26276ee18a482428e7c5726",
	}
	for lang, wantHex := range want {
		got, err := Digest(lang)
		if err != nil {
			t.Fatalf("Digest(%s): %v", lang, err)
		}
		if hex.EncodeToString(got) != wantHex {
			t.Errorf("Digest(%s) = %x, want %s", lang, got, wantHex)
		}
	}
	if _, err := Digest("klingon"); !errors.Is(err, ErrUnsupportedLanguage) {
		t.Errorf("Digest of unsupported language: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

func TestValidate(t *testing.T) {
	const frPrecomposed = "cligner gouffre monotone mutuel sortir rythme d\u00e9cider mignon f\u00e9brile refuge magique incolore"
	const jaU3000 = "なにごと\u3000せいじ\u3000いほう\u3000うせつ\u3000せきらんうん\u3000あらいぐま\u3000りよう\u3000だんあつ\u3000ちあん\u3000いれる\u3000ぬんちゃく\u3000そっけつ"
	const jaPlain = "なにごと せいじ いほう うせつ せきらんうん あらいぐま りよう だんあつ ちあん いれる ぬんちゃく そっけつ"

	cases := []struct {
		name     string
		language string
		mnemonic string
		wantErr  error // nil means valid
	}{
		{"valid 12 words", "english", validEN, nil},
		{"valid 24 words", "english",
			"mix dance drastic common pigeon fatigue cat chase hungry member boat harvest " +
				"shaft glass valid boss coffee garment shoe habit beauty plate father health", nil},
		{"bad checksum", "english", strings.Replace(validEN, "about", "abandon", 1), ErrChecksum},
		{"empty string", "english", "", ErrWordCount},
		{"single word", "english", "abandon", ErrWordCount},
		{"11 words", "english", strings.Join(strings.Fields(validEN)[:11], " "), ErrWordCount},
		{"13 words", "english", validEN + " abandon", ErrWordCount},
		{"double space", "english", strings.Replace(validEN, "abandon abandon", "abandon  abandon", 1), ErrWordCount},
		{"leading space", "english", " " + validEN, ErrWordCount},
		{"trailing space", "english", validEN + " ", ErrWordCount},
		{"trailing newline", "english", validEN + "\n", ErrUnknownWord},
		{"tabs instead of spaces", "english", strings.ReplaceAll(validEN, " ", "\t"), ErrWordCount},
		{"uppercase phrase", "english", strings.ToUpper(validEN), ErrUnknownWord},
		{"one uppercase word", "english", strings.Replace(validEN, "about", "ABOUT", 1), ErrUnknownWord},
		{"unknown word", "english", strings.Replace(validEN, "about", "zzzz", 1), ErrUnknownWord},
		{"all unknown words", "english", strings.Repeat("zzzz ", 11) + "zzzz", ErrUnknownWord},
		{"ideographic spaces in english", "english", strings.ReplaceAll(validEN, " ", "\u3000"), nil},
		{"wrong language for phrase", "french", validEN, ErrUnknownWord},
		{"french precomposed", "french", frPrecomposed, nil},
		{"french decomposed", "french", derive.NormalizeString(frPrecomposed), nil},
		{"japanese ideographic", "japanese", jaU3000, nil},
		{"japanese plain space", "japanese", jaPlain, nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wl, err := Load(c.language)
			if err != nil {
				t.Fatal(err)
			}
			err = wl.Validate(c.mnemonic)

			if c.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				if !wl.IsValid(c.mnemonic) {
					t.Error("IsValid() disagrees with Validate()")
				}
				return
			}
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, c.wantErr)
			}
			if wl.IsValid(c.mnemonic) {
				t.Error("IsValid() disagrees with Validate()")
			}
		})
	}
}

// TestValidateErrorLeaksNoSecret guards a security property: a rejection
// message must never echo the phrase back into logs or terminals.
func TestValidateErrorLeaksNoSecret(t *testing.T) {
	wl, err := Load("english")
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.Replace(validEN, "about", "hunter2word", 1)
	verr := wl.Validate(secret)
	if verr == nil {
		t.Fatal("expected the phrase to be rejected")
	}
	msg := verr.Error()
	for _, word := range strings.Fields(secret) {
		if strings.Contains(msg, word) {
			t.Fatalf("error message %q contains mnemonic word %q", msg, word)
		}
	}
}

func TestWordCountAndBits(t *testing.T) {
	if got := WordCount(validEN); got != 12 {
		t.Errorf("WordCount = %d, want 12", got)
	}
	if got := WordCount(strings.ReplaceAll(validEN, " ", "\u3000")); got != 12 {
		t.Errorf("WordCount with ideographic spaces = %d, want 12", got)
	}
	if got := MnemonicBits(validEN); got != 128 {
		t.Errorf("MnemonicBits = %d, want 128", got)
	}
	if got := MnemonicBits("abandon abandon"); got != 0 {
		t.Errorf("MnemonicBits of a non-mnemonic = %d, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

func TestToMnemonicKnownVectors(t *testing.T) {
	cases := []struct {
		language string
		entropy  string
		want     string
	}{
		{"english", "00000000000000000000000000000000", validEN},
		{"english", "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
			"legal winner thank year wave sausage worth useful legal winner thank yellow"},
		{"english", "ffffffffffffffffffffffffffffffff",
			"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"},
		{"english", "0000000000000000000000000000000000000000000000000000000000000000",
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
				"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " +
				"abandon abandon abandon art"},
	}
	for _, c := range cases {
		wl, err := Load(c.language)
		if err != nil {
			t.Fatal(err)
		}
		ent, err := hex.DecodeString(c.entropy)
		if err != nil {
			t.Fatal(err)
		}
		got, err := wl.ToMnemonic(ent)
		if err != nil {
			t.Fatalf("ToMnemonic: %v", err)
		}
		if got != c.want {
			t.Errorf("ToMnemonic(%s) =\n %q\nwant\n %q", c.entropy, got, c.want)
		}
		if err := wl.Validate(got); err != nil {
			t.Errorf("generated phrase failed validation: %v", err)
		}
	}
}

func TestToMnemonicRejectsBadEntropy(t *testing.T) {
	wl, err := Load("english")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 15, 17, 19, 21, 23, 25, 31, 33, 64} {
		if _, err := wl.ToMnemonic(make([]byte, n)); !errors.Is(err, ErrEntropyLength) {
			t.Errorf("ToMnemonic(%d bytes) error = %v, want ErrEntropyLength", n, err)
		}
	}
	if _, err := wl.ToMnemonic(nil); !errors.Is(err, ErrEntropyLength) {
		t.Errorf("ToMnemonic(nil) error = %v", err)
	}
}

func TestToMnemonicJapaneseUsesIdeographicSpace(t *testing.T) {
	wl, err := Load("japanese")
	if err != nil {
		t.Fatal(err)
	}
	m, err := wl.ToMnemonic(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m, IdeographicSpace) {
		t.Errorf("japanese mnemonic must be joined with U+3000: %q", m)
	}
	if strings.Contains(m, " ") {
		t.Errorf("japanese mnemonic must not contain plain spaces: %q", m)
	}
	if err := wl.Validate(m); err != nil {
		t.Errorf("japanese mnemonic failed validation: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

func TestGenerateAllLanguagesAndLengths(t *testing.T) {
	for _, lang := range Languages() {
		wl, err := Load(lang)
		if err != nil {
			t.Fatal(err)
		}
		for _, words := range WordCounts() {
			m, err := wl.Generate(words)
			if err != nil {
				t.Fatalf("Generate(%s, %d): %v", lang, words, err)
			}
			if got := WordCount(m); got != words {
				t.Errorf("Generate(%s, %d) produced %d words", lang, words, got)
			}
			if err := wl.Validate(m); err != nil {
				t.Errorf("Generate(%s, %d) produced an invalid phrase: %v", lang, words, err)
			}
		}
	}
}

func TestGenerateRejectsBadWordCount(t *testing.T) {
	wl, err := Load("english")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{-24, -1, 0, 1, 11, 13, 16, 23, 25, 100} {
		if _, err := wl.Generate(n); !errors.Is(err, ErrWordCount) {
			t.Errorf("Generate(%d) error = %v, want ErrWordCount", n, err)
		}
	}
}

func TestGenerateIsRandom(t *testing.T) {
	wl, err := Load("english")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		m, err := wl.Generate(12)
		if err != nil {
			t.Fatal(err)
		}
		if seen[m] {
			t.Fatalf("Generate repeated a phrase after %d draws", i)
		}
		seen[m] = true
	}
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkValidate(b *testing.B) {
	wl, err := Load("english")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := wl.Validate(validEN); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerate(b *testing.B) {
	wl, err := Load("english")
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		if _, err := wl.Generate(24); err != nil {
			b.Fatal(err)
		}
	}
}
