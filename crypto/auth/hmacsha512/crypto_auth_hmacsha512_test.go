package hmacsha512

import (
	"testing"
	"github.com/google/gofuzz"
	"bytes"
)

var testCount = 100000

func Test(t *testing.T) {
	// Test the key generation
	if len(KeyGen()) != KeyBytes() {
		t.Error("Generated key has the wrong length")
	}

	// Fuzzing
	f := fuzz.New()

	// Run tests
	for i := 0; i < testCount; i++ {
		var m,sk []byte
		var k [32]byte

		// Fuzz the test inputs
		f.Fuzz(&m)
		f.Fuzz(&sk)
		f.Fuzz(&k)

		// Create a tag
		h := Auth(m, k[:])

		// Verify the tag
		if !Verify(h, m, k[:]) {
			t.Errorf("Verification failed for: h: %x, m: %x, k: %x", h, m, k)
		}

		// Authenticate the same with the streaming functions
		state := Init(k[:])
		Update(state, m)
		sh := Final(state)

		if !Verify(sh, m, k[:]) || !bytes.Equal(sh, h) {
			t.Errorf("Steaming verification failed for: h: %x, m: %x, k: %x", h, m, k)
		}

		// Authenticate with streaming functions and an arbitrary length key
		state = Init(sk)
		Update(state, m)
		h = Final(state)

		// Verify the tag
		if len(h) != Bytes() {
			t.Errorf("Streaming verification failed for: h: %x, m: %x, k: %x", h, m, k)
		}
	}
}

