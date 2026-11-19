package bip39

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/cyberanchor/GoPassGen/internal/derive"
)

func embedded(t *testing.T, language string) []byte {
	t.Helper()
	data, err := wordlistFS.ReadFile("wordlists/" + language + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestEveryLanguageHasMatchingDigest(t *testing.T) {
	if len(wordlistDigests) != len(Languages()) {
		t.Errorf("%d digests for %d languages", len(wordlistDigests), len(Languages()))
	}
	for _, lang := range Languages() {
		if err := verifyDigest(lang, embedded(t, lang)); err != nil {
			t.Errorf("%s: %v", lang, err)
		}
	}
}

// TestTamperedWordlistIsDetected is the case that matters: one changed byte keeps
// 2048 unique words, so only the digest can notice it.
func TestTamperedWordlistIsDetected(t *testing.T) {
	data := embedded(t, "english")
	tampered := bytes.Replace(data, []byte("ability"), []byte("bbility"), 1)
	if bytes.Equal(data, tampered) {
		t.Fatal("test word not found")
	}
	if _, err := parseWordlist("english", tampered); err != nil {
		t.Fatalf("the list still parses, which is the point of this test: %v", err)
	}
	if err := verifyDigest("english", tampered); !errors.Is(err, ErrWordlistCorrupt) {
		t.Errorf("err = %v, want ErrWordlistCorrupt", err)
	}
}

// TestLoadChecksTheDigest makes the recorded digest wrong instead of the embedded
// file, which cannot be changed from a test.
func TestLoadChecksTheDigest(t *testing.T) {
	const lang = "korean"
	saved := wordlistDigests[lang]
	wordlistDigests[lang] = strings.Repeat("0", 64)
	cacheMu.Lock()
	cached := cache[lang]
	delete(cache, lang)
	cacheMu.Unlock()
	defer func() {
		wordlistDigests[lang] = saved
		cacheMu.Lock()
		delete(cache, lang)
		if cached != nil {
			cache[lang] = cached
		}
		cacheMu.Unlock()
	}()

	if wl, err := Load(lang); !errors.Is(err, ErrWordlistCorrupt) || wl != nil {
		t.Errorf("wl = %v, err = %v, want ErrWordlistCorrupt", wl, err)
	}
}

func TestParseWordlistRejectsBadLists(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(string(embedded(t, "english"))), "\n")

	short := strings.Join(lines[:len(lines)-1], "\n")
	if _, err := parseWordlist("english", []byte(short)); !errors.Is(err, ErrWordlistCorrupt) {
		t.Errorf("short list: err = %v", err)
	}

	dup := append([]string(nil), lines...)
	dup[len(dup)-1] = dup[0]
	_, err := parseWordlist("english", []byte(strings.Join(dup, "\n")))
	if !errors.Is(err, ErrWordlistCorrupt) || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate word: err = %v", err)
	}

	crlf := strings.Join(lines, "\r\n")
	if _, err := parseWordlist("english", []byte(crlf)); err != nil {
		t.Errorf("CRLF line endings: %v", err)
	}
}

// entropyOf recovers the entropy bytes that a valid phrase encodes.
func entropyOf(t *testing.T, wl *Wordlist, phrase string) []byte {
	t.Helper()
	words := strings.Split(derive.NormalizeString(phrase), " ")
	var bits []byte
	for _, w := range words {
		idx, ok := wl.Index(w)
		if !ok {
			t.Fatalf("unknown word %q", w)
		}
		for b := 10; b >= 0; b-- {
			bits = append(bits, byte(idx>>uint(b))&1)
		}
	}
	entropy := make([]byte, len(bits)/33*32/8)
	for i := range entropy {
		for j := 0; j < 8; j++ {
			entropy[i] = entropy[i]<<1 | bits[i*8+j]
		}
	}
	return entropy
}

// TestGeneratedPhrasesUseAllEntropy would catch a generator that fills only part
// of the entropy buffer. Such phrases still look valid and pass every checksum.
func TestGeneratedPhrasesUseAllEntropy(t *testing.T) {
	wl, err := Load("english")
	if err != nil {
		t.Fatal(err)
	}
	const samples = 200
	for _, words := range WordCounts() {
		var seen [][256]bool
		for i := 0; i < samples; i++ {
			phrase, err := wl.Generate(words)
			if err != nil {
				t.Fatal(err)
			}
			entropy := entropyOf(t, wl, phrase)
			if seen == nil {
				seen = make([][256]bool, len(entropy))
			}
			for pos, b := range entropy {
				seen[pos][b] = true
			}
		}
		bits, _ := StrengthBits(words)
		if len(seen) != bits/8 {
			t.Errorf("%d words: %d entropy bytes, want %d", words, len(seen), bits/8)
		}
		for pos := range seen {
			distinct := 0
			for _, s := range seen[pos] {
				if s {
					distinct++
				}
			}
			// 200 random bytes give about 140 distinct values.
			if distinct < 64 {
				t.Errorf("%d words: entropy byte %d took only %d values", words, pos, distinct)
			}
		}
	}
}

func TestEveryChecksumBitIsChecked(t *testing.T) {
	wl, err := Load("english")
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range WordCounts() {
		bits, _ := StrengthBits(count)
		entropy := bytes.Repeat([]byte{0x5a}, bits/8)
		phrase, err := wl.ToMnemonic(entropy)
		if err != nil {
			t.Fatal(err)
		}
		words := strings.Split(phrase, " ")
		last, _ := wl.Index(words[len(words)-1])
		// The checksum occupies the low bits of the last word.
		for bit := 0; bit < bits/32; bit++ {
			words[len(words)-1], _ = wl.Word(last ^ 1<<uint(bit))
			if err := wl.Validate(strings.Join(words, " ")); !errors.Is(err, ErrChecksum) {
				t.Errorf("%d words, checksum bit %d flipped: err = %v", count, bit, err)
			}
		}
	}
}

func TestGenerateVerifiesItsOwnResult(t *testing.T) {
	wl, err := Load("english")
	if err != nil {
		t.Fatal(err)
	}
	broken := *wl
	broken.words = make([]string, len(wl.words))
	for i, w := range wl.words {
		broken.words[i] = "x" + w
	}
	if _, err := broken.Generate(12); err == nil || !strings.Contains(err.Error(), "self-validation") {
		t.Errorf("err = %v, want a self-validation failure", err)
	}
}

// TestEntropyBuffersAreErased covers the one-byte-per-bit arrays, which hold the
// whole entropy in plain sight.
func TestEntropyBuffersAreErased(t *testing.T) {
	wl, err := Load("english")
	if err != nil {
		t.Fatal(err)
	}
	var tracked [][]byte
	derive.SecretHook = func(b []byte) { tracked = append(tracked, b) }
	defer func() { derive.SecretHook = nil }()

	phrase, err := wl.Generate(24)
	if err != nil {
		t.Fatal(err)
	}
	if err := wl.Validate(phrase); err != nil {
		t.Fatal(err)
	}
	if err := wl.Validate(strings.Replace(phrase, " ", " zzzz ", 1)); err == nil {
		t.Fatal("a phrase with an unknown word passed")
	}
	if len(tracked) < 4 {
		t.Fatalf("only %d buffers tracked", len(tracked))
	}
	for i, b := range tracked {
		if strings.Trim(string(b[:cap(b)]), "\x00") != "" {
			t.Errorf("tracked buffer %d (%d bytes) was not erased", i, cap(b))
		}
	}
}
