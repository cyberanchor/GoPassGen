package passgen

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"gopassgen/internal/bip39"
	"gopassgen/internal/derive"
)

// vectorFile is produced by the reference implementation (PyPassGen 1.3.5 with
// python-mnemonic). It is the contract this port exists to satisfy: if any of
// these fail, the Go build is wrong — never "fix" a vector.
const vectorFile = "testdata/vectors.json"

type vectors struct {
	PasswordVectors []struct {
		Name     string `json:"name"`
		Language string `json:"language"`
		Mnemonic string `json:"mnemonic"`
		Length   int    `json:"length"`
		Password string `json:"password"`
	} `json:"password_vectors"`

	MnemonicVectors []struct {
		Language string `json:"language"`
		Entropy  string `json:"entropy"`
		Mnemonic string `json:"mnemonic"`
	} `json:"mnemonic_vectors"`

	SeedVectors []struct {
		Name     string `json:"name"`
		Language string `json:"language"`
		Mnemonic string `json:"mnemonic"`
		Seed     string `json:"seed"`
	} `json:"seed_vectors"`

	CheckVectors []struct {
		Language string `json:"language"`
		Mnemonic string `json:"mnemonic"`
		Valid    bool   `json:"valid"`
		Desc     string `json:"desc"`
	} `json:"check_vectors"`
}

func loadVectors(t *testing.T) *vectors {
	t.Helper()
	data, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatalf("reading %s: %v", vectorFile, err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parsing %s: %v", vectorFile, err)
	}
	if len(v.PasswordVectors) == 0 || len(v.SeedVectors) == 0 ||
		len(v.MnemonicVectors) == 0 || len(v.CheckVectors) == 0 {
		t.Fatal("vector file is incomplete")
	}
	return &v
}

// TestCompatSeedVectors covers stage 1-2 for every language. Cheap: 2048
// iterations each.
func TestCompatSeedVectors(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.SeedVectors {
		t.Run(c.Name, func(t *testing.T) {
			got := hex.EncodeToString(derive.Seed(c.Mnemonic, ""))
			if got != c.Seed {
				t.Errorf("seed mismatch\n got:  %s\n want: %s", got, c.Seed)
			}
		})
	}
}

// TestCompatMnemonicVectors covers entropy-to-phrase encoding for every
// language, including the Japanese ideographic-space delimiter.
func TestCompatMnemonicVectors(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.MnemonicVectors {
		t.Run(c.Language+"/"+c.Entropy[:8], func(t *testing.T) {
			wl, err := bip39.Load(c.Language)
			if err != nil {
				t.Fatal(err)
			}
			ent, err := hex.DecodeString(c.Entropy)
			if err != nil {
				t.Fatal(err)
			}
			got, err := wl.ToMnemonic(ent)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.Mnemonic {
				t.Errorf("mnemonic mismatch\n got:  %q\n want: %q", got, c.Mnemonic)
			}
		})
	}
}

// TestCompatCheckVectors asserts that validation accepts and rejects exactly
// the same phrases as python-mnemonic, whitespace quirks included.
func TestCompatCheckVectors(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.CheckVectors {
		t.Run(c.Desc, func(t *testing.T) {
			wl, err := bip39.Load(c.Language)
			if err != nil {
				t.Fatal(err)
			}
			if got := wl.IsValid(c.Mnemonic); got != c.Valid {
				t.Errorf("IsValid = %v, python says %v", got, c.Valid)
			}
		})
	}
}

// TestCompatPasswordVectors is the end-to-end contract: 22 vectors across all
// seven languages and lengths 1, 12, 16, 24, 32, 100 and 256.
//
// Each vector costs 1,000,000 PBKDF2-HMAC-SHA512 iterations, so the suite runs
// in parallel and is trimmed in -short mode.
func TestCompatPasswordVectors(t *testing.T) {
	v := loadVectors(t)
	for i, c := range v.PasswordVectors {
		c := c
		if testing.Short() && i%7 != 0 {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			gen, err := New(c.Language, nil)
			if err != nil {
				t.Fatal(err)
			}
			pw, err := gen.Password(c.Mnemonic, c.Length)
			if err != nil {
				t.Fatalf("Password: %v", err)
			}
			defer derive.Wipe(pw)

			if string(pw) != c.Password {
				t.Errorf("password mismatch (language=%s length=%d)\n got:  %q\n want: %q",
					c.Language, c.Length, pw, c.Password)
			}
			if len(pw) != c.Length {
				t.Errorf("length = %d, want %d", len(pw), c.Length)
			}
		})
	}
}

// TestCompatVectorCoverage fails if the vector file stops covering a language
// or a boundary length, which would let a regression slip through unnoticed.
func TestCompatVectorCoverage(t *testing.T) {
	v := loadVectors(t)

	langs := map[string]bool{}
	lengths := map[int]bool{}
	for _, c := range v.PasswordVectors {
		langs[c.Language] = true
		lengths[c.Length] = true
	}
	for _, l := range bip39.Languages() {
		if !langs[l] {
			t.Errorf("no password vector covers language %q", l)
		}
	}
	for _, n := range []int{1, 12, 16, 32, 100, derive.MaxPasswordLength} {
		if !lengths[n] {
			t.Errorf("no password vector covers length %d", n)
		}
	}
}
