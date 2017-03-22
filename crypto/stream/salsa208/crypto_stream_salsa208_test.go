package salsa208

import (
	"testing"
	"bytes"
	"github.com/google/gofuzz"
)

var TestCount = 100000

func Test(t *testing.T) {
	// Test the key generation
	if len(KeyGen()) != KeyBytes() {
		t.Error("Generated key has the wrong length")
	}

	// Fuzzing
	f := fuzz.New()

	// Run tests
	for i := 0; i < TestCount; i++ {
		var c, m, r, d []byte
		var n [8]byte

		// Generate random data
		f.Fuzz(&m)
		f.Fuzz(&n)
		k := KeyGen()

		// Generate pseudo-random data
		r = Random(len(m), n[:], k)

		// Perform XOR
		d = make([]byte, len(m))
		for i := range r {
			d[i] = r[i] ^ m[i]
		}

		// Generate a ciphertext
		c = XOR(m, n[:], k)
		if !bytes.Equal(c, d) {
			t.Errorf("XOR failed for m: %x, n: %x, k: %x", m, n, k)
			t.FailNow()
		}
	}
}

