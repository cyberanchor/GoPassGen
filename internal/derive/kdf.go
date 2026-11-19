package derive

import (
	"context"
	"crypto/sha512"
	"crypto/subtle"
	"encoding"
	"fmt"
	"hash"
)

// cancelCheckMask makes PBKDF2 look at its context every 1024 iterations: often
// enough that Ctrl-C feels immediate, rare enough to cost nothing measurable.
const cancelCheckMask = 1<<10 - 1

// SecretHook, when set by a test, receives every internal buffer that holds
// secret data, so the test can verify that each one ends up zeroed.
var SecretHook func([]byte)

// TrackSecret reports a secret buffer to SecretHook and returns it unchanged.
func TrackSecret(b []byte) []byte {
	if SecretHook != nil {
		SecretHook(b)
	}
	return b
}

// hmacSHA512 is HMAC-SHA512 whose key-dependent state can be erased.
//
// crypto/hmac keeps "key XOR ipad" and "key XOR opad" in private fields, from
// which the key is recovered with a plain XOR. Nothing outside the package can
// clear them, and golang.org/x/crypto/pbkdf2 builds on the same type, so a key
// wiped by the caller would stay readable in memory. The construction here is
// the textbook one from RFC 2104, with all state in reach of wipe.
type hmacSHA512 struct {
	inner, outer hash.Hash

	// innerState and outerState are the hash states after absorbing the pads.
	// Restoring them saves two SHA-512 compressions per call, which is what
	// keeps 1,000,000 iterations affordable. They are equivalent to the key.
	innerState, outerState []byte
	restoreInner           encoding.BinaryUnmarshaler
	restoreOuter           encoding.BinaryUnmarshaler
}

func newHMAC(key []byte) *hmacSHA512 {
	pad := TrackSecret(make([]byte, sha512.BlockSize))
	defer Wipe(pad)

	if len(key) > sha512.BlockSize {
		h := sha512.New()
		h.Write(key)
		h.Sum(pad[:0])
		scrubHash(h)
	} else {
		copy(pad, key)
	}

	m := &hmacSHA512{inner: sha512.New(), outer: sha512.New()}
	for i := range pad {
		pad[i] ^= 0x36
	}
	m.inner.Write(pad)
	for i := range pad {
		pad[i] ^= 0x36 ^ 0x5c
	}
	m.outer.Write(pad)

	m.innerState, m.restoreInner = saveHashState(m.inner)
	m.outerState, m.restoreOuter = saveHashState(m.outer)
	return m
}

func saveHashState(h hash.Hash) ([]byte, encoding.BinaryUnmarshaler) {
	marshaler, ok := h.(encoding.BinaryMarshaler)
	restorer, ok2 := h.(encoding.BinaryUnmarshaler)
	if !ok || !ok2 {
		panic(fmt.Sprintf("derive: %T cannot save its state", h))
	}
	state, err := marshaler.MarshalBinary()
	if err != nil {
		panic("derive: saving SHA-512 state: " + err.Error())
	}
	return TrackSecret(state), restorer
}

func mustRestore(r encoding.BinaryUnmarshaler, state []byte) {
	if err := r.UnmarshalBinary(state); err != nil {
		panic("derive: restoring SHA-512 state: " + err.Error())
	}
}

// sum stores HMAC(key, a || b) in out, which must have room for sha512.Size
// bytes. out may overlap a or b.
func (m *hmacSHA512) sum(out, a, b []byte) {
	mustRestore(m.restoreInner, m.innerState)
	m.inner.Write(a)
	m.inner.Write(b)
	m.inner.Sum(out[:0])

	mustRestore(m.restoreOuter, m.outerState)
	m.outer.Write(out[:sha512.Size])
	m.outer.Sum(out[:0])
}

// wipe erases everything derived from the key. The value must not be used again.
func (m *hmacSHA512) wipe() {
	Wipe(m.innerState)
	Wipe(m.outerState)
	scrubHash(m.inner)
	scrubHash(m.outer)
}

// scrubHash overwrites both the chaining value and the partial-block buffer,
// which Reset alone leaves in place.
func scrubHash(h hash.Hash) {
	var zeros [sha512.BlockSize - 1]byte
	h.Reset()
	h.Write(zeros[:])
	h.Reset()
}

// pbkdf2Block1 is INT(1) from RFC 8018. Both PBKDF2 stages produce exactly one
// SHA-512 block, so no other block index is ever needed.
var pbkdf2Block1 = []byte{0, 0, 0, 1}

// pbkdf2SHA512 computes PBKDF2-HMAC-SHA512 with dkLen = KeyLen.
//
// It stops with ctx.Err() soon after ctx is cancelled, and leaves no
// key-dependent data behind except the returned key.
func pbkdf2SHA512(ctx context.Context, password, salt []byte, iterations int) ([]byte, error) {
	mac := newHMAC(password)
	defer mac.wipe()

	u := TrackSecret(make([]byte, KeyLen))
	defer Wipe(u)
	out := make([]byte, KeyLen)

	mac.sum(u, salt, pbkdf2Block1)
	copy(out, u)
	for i := 1; i < iterations; i++ {
		if i&cancelCheckMask == 0 {
			if err := ctx.Err(); err != nil {
				Wipe(out)
				return nil, err
			}
		}
		mac.sum(u, u, nil)
		subtle.XORBytes(out, out, u)
	}
	return out, nil
}
