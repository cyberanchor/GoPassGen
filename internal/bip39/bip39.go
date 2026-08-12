// Package bip39 implements the subset of BIP-39 that GoPassGen needs:
// wordlist loading, checksum validation and mnemonic generation.
//
// Behaviour is matched to the Python `mnemonic` package that PyPassGen uses,
// including its quirks — see Wordlist.Validate for the whitespace rule.
package bip39

import (
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"gopassgen/internal/derive"
)

//go:embed wordlists/*.txt
var wordlistFS embed.FS

// WordlistSize is the number of words in every BIP-39 wordlist.
const WordlistSize = 2048

// IdeographicSpace is the delimiter the reference implementation uses to join
// Japanese mnemonics. NFKD folds it to a plain space before hashing.
const IdeographicSpace = "\u3000"

// Errors returned by this package. Match them with errors.Is.
var (
	// ErrUnsupportedLanguage is returned for a language with no embedded wordlist.
	ErrUnsupportedLanguage = errors.New("unsupported language")
	// ErrWordCount is returned when the phrase does not have 12, 15, 18, 21 or 24 words.
	ErrWordCount = errors.New("invalid word count")
	// ErrUnknownWord is returned when a word is absent from the wordlist.
	ErrUnknownWord = errors.New("word not in wordlist")
	// ErrChecksum is returned when the BIP-39 checksum does not match.
	ErrChecksum = errors.New("checksum mismatch")
	// ErrEntropyLength is returned by ToMnemonic for an unusable entropy size.
	ErrEntropyLength = errors.New("entropy length must be 16, 20, 24, 28 or 32 bytes")
	// ErrWordlistCorrupt is returned when an embedded wordlist fails its self-check.
	ErrWordlistCorrupt = errors.New("wordlist is corrupt")
)

// strengthByWords maps a word count to its entropy size in bits (STRENGTH_MAP).
var strengthByWords = map[int]int{12: 128, 15: 160, 18: 192, 21: 224, 24: 256}

// supported mirrors SUPPORTED_LANGUAGES in pypassgen.py.
var supported = []string{
	"english",
	"french",
	"spanish",
	"italian",
	"japanese",
	"korean",
	"chinese_simplified",
}

// Languages returns the supported language identifiers, sorted.
func Languages() []string {
	out := append([]string(nil), supported...)
	sort.Strings(out)
	return out
}

// IsSupported reports whether the language has an embedded wordlist.
func IsSupported(language string) bool {
	for _, l := range supported {
		if l == language {
			return true
		}
	}
	return false
}

// WordCounts returns the accepted mnemonic lengths, sorted.
func WordCounts() []int {
	out := make([]int, 0, len(strengthByWords))
	for k := range strengthByWords {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// StrengthBits returns the entropy size for a word count, and whether the
// word count is valid.
func StrengthBits(words int) (int, bool) {
	s, ok := strengthByWords[words]
	return s, ok
}

// Digest returns the SHA-256 of the embedded wordlist file for a language.
// It lets the self-test detect a corrupted or tampered binary.
func Digest(language string) ([]byte, error) {
	if !IsSupported(language) {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedLanguage, language)
	}
	data, err := wordlistFS.ReadFile("wordlists/" + language + ".txt")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWordlistCorrupt, err)
	}
	sum := sha256.Sum256(data)
	return sum[:], nil
}

// Wordlist is an immutable, concurrency-safe BIP-39 wordlist.
type Wordlist struct {
	language  string
	words     []string
	index     map[string]int
	delimiter string
}

var (
	cacheMu sync.Mutex
	cache   = map[string]*Wordlist{}
)

// Load returns the wordlist for a language. Results are cached; the returned
// value is read-only and safe for concurrent use.
func Load(language string) (*Wordlist, error) {
	if !IsSupported(language) {
		return nil, fmt.Errorf("%w: %q (supported: %s)",
			ErrUnsupportedLanguage, language, strings.Join(Languages(), ", "))
	}

	cacheMu.Lock()
	defer cacheMu.Unlock()
	if wl, ok := cache[language]; ok {
		return wl, nil
	}

	data, err := wordlistFS.ReadFile("wordlists/" + language + ".txt")
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read embedded wordlist for %q: %v",
			ErrWordlistCorrupt, language, err)
	}

	words := make([]string, 0, WordlistSize)
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if w := strings.TrimSpace(line); w != "" {
			words = append(words, w)
		}
	}
	if len(words) != WordlistSize {
		return nil, fmt.Errorf("%w: %s has %d words, want %d",
			ErrWordlistCorrupt, language, len(words), WordlistSize)
	}

	index := make(map[string]int, WordlistSize)
	for i, w := range words {
		// list.index() returns the first match; keep the same semantics.
		if _, dup := index[w]; !dup {
			index[w] = i
		}
	}
	if len(index) != WordlistSize {
		return nil, fmt.Errorf("%w: %s contains duplicate words", ErrWordlistCorrupt, language)
	}

	delimiter := " "
	if language == "japanese" {
		delimiter = IdeographicSpace
	}

	wl := &Wordlist{language: language, words: words, index: index, delimiter: delimiter}
	cache[language] = wl
	return wl, nil
}

// Language returns the wordlist identifier.
func (wl *Wordlist) Language() string { return wl.language }

// Delimiter returns the string used to join generated mnemonics.
func (wl *Wordlist) Delimiter() string { return wl.delimiter }

// Word returns the word at index i, which must be in [0, 2048).
func (wl *Wordlist) Word(i int) (string, bool) {
	if i < 0 || i >= len(wl.words) {
		return "", false
	}
	return wl.words[i], true
}

// Index returns the position of a word, and whether it is present.
// The word must already be NFKD-normalized.
func (wl *Wordlist) Index(word string) (int, bool) {
	i, ok := wl.index[word]
	return i, ok
}

// Validate checks a mnemonic and explains why it is rejected.
//
// Two behaviours are inherited from the reference implementation and must not
// be "improved":
//
//   - The phrase is NFKD-normalized and then split on a single literal space.
//     Double spaces, tabs and leading or trailing whitespace therefore make it
//     invalid — the same as in Python. Trimming or collapsing whitespace here
//     would accept phrases that the Python tool rejects and, worse, would hash
//     a different byte string and silently produce a different password.
//   - NFKD folds U+3000 to U+0020, so a Japanese phrase joined with
//     ideographic spaces validates, and so does an English one.
//
// Error messages never contain the mnemonic or any of its words; only the
// 1-based position of the offending word is reported.
func (wl *Wordlist) Validate(mnemonic string) error {
	words := strings.Split(derive.NormalizeString(mnemonic), " ")

	if _, ok := strengthByWords[len(words)]; !ok {
		return fmt.Errorf("%w: got %d words, want one of %v",
			ErrWordCount, len(words), WordCounts())
	}

	bits := make([]byte, 0, len(words)*11)
	for i, w := range words {
		idx, ok := wl.index[w]
		if !ok {
			return fmt.Errorf("%w: word %d is not in the %s wordlist",
				ErrUnknownWord, i+1, wl.language)
		}
		for b := 10; b >= 0; b-- {
			bits = append(bits, byte((idx>>uint(b))&1))
		}
	}

	total := len(bits)
	entBits := total / 33 * 32
	csBits := total / 33

	entropy := make([]byte, entBits/8)
	for i := 0; i < entBits; i++ {
		if bits[i] == 1 {
			entropy[i/8] |= 1 << uint(7-i%8)
		}
	}

	sum := sha256.Sum256(entropy)
	derive.Wipe(entropy)

	for i := 0; i < csBits; i++ {
		want := (sum[i/8] >> uint(7-i%8)) & 1
		if bits[entBits+i] != want {
			return ErrChecksum
		}
	}
	return nil
}

// IsValid reports whether the mnemonic passes Validate. It is the boolean
// equivalent of the reference implementation's check().
func (wl *Wordlist) IsValid(mnemonic string) bool {
	return wl.Validate(mnemonic) == nil
}

// WordCount returns the number of words as Validate counts them.
func WordCount(mnemonic string) int {
	return len(strings.Split(derive.NormalizeString(mnemonic), " "))
}

// MnemonicBits returns the entropy carried by a mnemonic of this word count,
// or 0 if the word count is not a valid BIP-39 length.
func MnemonicBits(mnemonic string) int {
	return strengthByWords[WordCount(mnemonic)]
}

// ToMnemonic encodes entropy as a mnemonic phrase (Mnemonic.to_mnemonic).
func (wl *Wordlist) ToMnemonic(entropy []byte) (string, error) {
	switch len(entropy) {
	case 16, 20, 24, 28, 32:
	default:
		return "", fmt.Errorf("%w: got %d", ErrEntropyLength, len(entropy))
	}

	sum := sha256.Sum256(entropy)
	csBits := len(entropy) * 8 / 32

	bits := make([]byte, 0, len(entropy)*8+csBits)
	for _, b := range entropy {
		for i := 7; i >= 0; i-- {
			bits = append(bits, (b>>uint(i))&1)
		}
	}
	for i := 0; i < csBits; i++ {
		bits = append(bits, (sum[i/8]>>uint(7-i%8))&1)
	}

	words := make([]string, 0, len(bits)/11)
	for i := 0; i < len(bits)/11; i++ {
		idx := 0
		for j := 0; j < 11; j++ {
			idx = idx<<1 | int(bits[i*11+j])
		}
		words = append(words, wl.words[idx])
	}
	return strings.Join(words, wl.delimiter), nil
}

// Generate creates a fresh mnemonic of numWords words using crypto/rand.
//
// The result is verified with Validate before being returned: a silent
// entropy or encoding fault would otherwise produce an unusable phrase.
func (wl *Wordlist) Generate(numWords int) (string, error) {
	strength, ok := strengthByWords[numWords]
	if !ok {
		return "", fmt.Errorf("%w: got %d, want one of %v", ErrWordCount, numWords, WordCounts())
	}

	entropy := make([]byte, strength/8)
	if _, err := rand.Read(entropy); err != nil {
		return "", fmt.Errorf("entropy source failed: %w", err)
	}

	mnemonic, err := wl.ToMnemonic(entropy)
	derive.Wipe(entropy)
	if err != nil {
		return "", err
	}
	if err := wl.Validate(mnemonic); err != nil {
		return "", fmt.Errorf("generated mnemonic failed self-validation: %w", err)
	}
	return mnemonic, nil
}
