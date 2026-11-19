//go:build go1.24

package derive

import (
	"bytes"
	"context"
	"crypto/pbkdf2"
	"crypto/sha512"
	"math/rand"
	"testing"
)

// TestPBKDF2MatchesStandardLibrary compares against crypto/pbkdf2, which exists
// from Go 1.24 on. Password lengths cross the SHA-512 block size, because a long
// 24-word phrase is hashed first.
func TestPBKDF2MatchesStandardLibrary(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for _, pwLen := range []int{0, 1, 64, 127, 128, 129, 400} {
		for _, saltLen := range []int{0, 1, 8, 200} {
			for _, iterations := range []int{1, 2, 1023, 1024, 1025} {
				pw, salt := make([]byte, pwLen), make([]byte, saltLen)
				r.Read(pw)
				r.Read(salt)
				want, err := pbkdf2.Key(sha512.New, string(pw), salt, iterations, KeyLen)
				if err != nil {
					t.Fatal(err)
				}
				got, err := pbkdf2SHA512(context.Background(), pw, salt, iterations)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("password %d, salt %d, %d iterations: differs", pwLen, saltLen, iterations)
				}
			}
		}
	}
}
