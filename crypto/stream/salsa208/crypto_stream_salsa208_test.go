package salsa208

import (
	"bytes"
	"github.com/google/gofuzz"
	"testing"
)

var TestCount = 100000

func TestSalsa208(t *testing.T) {
	// Test the key generation
	if *GenerateKey() == (Key{}) {
		t.Error("Generated key is zero")
	}

	// Fuzzing
	fm := fuzz.New()
	fn := fuzz.New().NilChance(0)

	// Run tests
	for i := 0; i < TestCount; i++ {
		var c, m, r, d []byte
		n := new(Nonce)

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

		// Check if in-place encryption works
		XORKeyStream(m, m, n, k)
		if !bytes.Equal(c, m) {
			t.Errorf("In place encryption failed for m: %x, n: %x, k: %x", m, n, k)
			t.FailNow()
		}
	}
}
