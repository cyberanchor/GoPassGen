package derive

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func hmacOf(key, msg []byte) []byte {
	m := newHMAC(key)
	defer m.wipe()
	out := make([]byte, sha512.Size)
	m.sum(out, msg, nil)
	return out
}

// TestHMACKnownVectors uses the HMAC-SHA-512 vectors from RFC 4231.
func TestHMACKnownVectors(t *testing.T) {
	cases := []struct {
		name string
		key  []byte
		msg  string
		want string
	}{
		{
			"case 1", bytes.Repeat([]byte{0x0b}, 20), "Hi There",
			"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde" +
				"daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
		},
		{
			"key longer than a block", bytes.Repeat([]byte{0xaa}, 131),
			"Test Using Larger Than Block-Size Key - Hash Key First",
			"80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352" +
				"6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
		},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(hmacOf(c.key, []byte(c.msg))); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestHMACMatchesStandardLibrary(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	// The interesting key sizes sit around the 128-byte SHA-512 block.
	for _, keyLen := range []int{0, 1, 64, 127, 128, 129, 200, 1000} {
		for _, msgLen := range []int{0, 1, 64, 111, 112, 127, 128, 129, 300} {
			key, msg := make([]byte, keyLen), make([]byte, msgLen)
			r.Read(key)
			r.Read(msg)
			std := hmac.New(sha512.New, key)
			std.Write(msg)
			if !bytes.Equal(hmacOf(key, msg), std.Sum(nil)) {
				t.Fatalf("key %d bytes, message %d bytes: differs from crypto/hmac", keyLen, msgLen)
			}
		}
	}
}

func TestHMACIsReusable(t *testing.T) {
	m := newHMAC([]byte("key"))
	defer m.wipe()
	first, second := make([]byte, sha512.Size), make([]byte, sha512.Size)
	m.sum(first, []byte("message"), nil)
	m.sum(second, []byte("mess"), []byte("age"))
	if !bytes.Equal(first, second) {
		t.Error("a second call or a split message changed the result")
	}
}

func TestPBKDF2KnownVectors(t *testing.T) {
	cases := []struct {
		iterations int
		want       string
	}{
		{1, "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252" +
			"c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"},
		{2, "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c" +
			"f76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e"},
		{4096, "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5" +
			"143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5"},
	}
	for _, c := range cases {
		got, err := pbkdf2SHA512(context.Background(), []byte("password"), []byte("salt"), c.iterations)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != c.want {
			t.Errorf("%d iterations: got %x, want %s", c.iterations, got, c.want)
		}
	}
}

func TestContextVariantsMatchPlainOnes(t *testing.T) {
	ctx := context.Background()
	seed, err := SeedContext(ctx, "a phrase", "x")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seed, Seed("a phrase", "x")) {
		t.Error("SeedContext differs from Seed")
	}
	if testing.Short() {
		return
	}
	key, err := KeyContext(ctx, seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, Key(seed)) {
		t.Error("KeyContext differs from Key")
	}
}

func TestDerivationStopsWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := KeyContext(ctx, make([]byte, KeyLen))
		done <- err
	}()
	time.Sleep(time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("derivation ignored the cancellation")
	}

	if _, _, err := FromMnemonicContext(ctx, "phrase", "", 12, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("FromMnemonicContext: err = %v, want context.Canceled", err)
	}
	if _, err := SeedContext(ctx, strings.Repeat("phrase ", 4), ""); !errors.Is(err, context.Canceled) {
		t.Errorf("SeedContext: err = %v, want context.Canceled", err)
	}
}

// TestPipelineErasesEveryInternalSecret covers the phrase bytes, salt, HMAC pads
// and saved states, PBKDF2 blocks, the seed, the key and the stream blocks.
func TestPipelineErasesEveryInternalSecret(t *testing.T) {
	var tracked [][]byte
	SecretHook = func(b []byte) { tracked = append(tracked, b) }
	defer func() { SecretHook = nil }()

	pw, _, err := FromMnemonic("some phrase that is long enough to matter", "secret", 16, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != 16 {
		t.Fatalf("password length %d", len(pw))
	}
	// One PBKDF2 run alone tracks its pad, two saved states and its block.
	if len(tracked) < 15 {
		t.Fatalf("only %d buffers tracked; the hook is not wired up", len(tracked))
	}
	for i, b := range tracked {
		if strings.Trim(string(b[:cap(b)]), "\x00") != "" {
			t.Errorf("tracked buffer %d (%d bytes) was not erased", i, cap(b))
		}
	}
}

func TestHMACWipeClearsSavedState(t *testing.T) {
	m := newHMAC([]byte("key"))
	m.wipe()
	for _, state := range [][]byte{m.innerState, m.outerState} {
		if strings.Trim(string(state), "\x00") != "" {
			t.Error("saved hash state survived wipe")
		}
	}
}
