package chacha20

import (
	"bytes"
	"github.com/google/gofuzz"
	"testing"
)

var TestCount = 100000

func TestChaCha20(t *testing.T) {
	// Test the key generation
	if *GenerateKey() == ([KeyBytes]byte{}) {
		t.Error("Generated key is zero")
	}

	// Fuzzing
	fm := fuzz.New()
	fn := fuzz.New().NilChance(0)

	// Run tests
	for i := 0; i < TestCount; i++ {
		var c, m, m2, r, d []byte
		n := new([NonceBytes]byte)

		// Generate random data
		fm.Fuzz(&m)
		fn.Fuzz(&n)
		k := GenerateKey()

		// Generate pseudo-random data
		r = make([]byte, len(m))
		KeyStream(r, n, k)

		// Perform XOR
		d = make([]byte, len(m))
		for i := range r {
			d[i] = r[i] ^ m[i]
		}

		// Generate a ciphertext
		c = make([]byte, len(m))
		XORKeyStream(c, m, n, k)
		if !bytes.Equal(c, d) {
			t.Errorf("Encryption failed for m: %x, n: %x, k: %x", m, n, k)
			t.FailNow()
		}

		// Generate one with IC
		XORKeyStreamIC(c, m, n, k, 0)
		if !bytes.Equal(c, d) {
			t.Errorf("Encryption with IC failed for m: %x, n: %x, k: %x", m, n, k)
			t.FailNow()
		}

		// Check if in-place encryption works
		m2 = make([]byte, len(m))
		copy(m2, m)
		XORKeyStream(m2, m2, n, k)
		if !bytes.Equal(c, m2) {
			t.Errorf("In place encryption failed for m: %x, n: %x, k: %x", m, n, k)
			t.FailNow()
		}

		// Check again with IC
		XORKeyStreamIC(m, m, n, k, 0)
		if !bytes.Equal(c, m2) {
			t.Errorf("In place encryption with IC failed for m: %x, n: %x, k: %x", m, n, k)
			t.FailNow()
		}
	}
}
