package generichash

import (
	"bytes"
	"github.com/google/gofuzz"
	"testing"
)

var testCount = 25000

func Test(t *testing.T) {
	// Check algorithm name
	if Primitive != "blake2b" {
		t.Errorf("Incorrect primitive: %s", Primitive)
	}

	// Test the key generation
	if bytes.Equal(GenerateKey(), make([]byte, KeyBytes)) {
		t.Error("Generated key is zero")
	}

	// Fuzzing
	f := fuzz.New().NilChance(0.01).NumElements(1, 1024)

	// Check size
	s := NewBlake2b(BytesMin, nil)

	// Check block size
	if s.BlockSize() != 1 {
		t.Error("Sum block size incorrect")
	}

	// Run tests
	for i := 0; i < testCount; i++ {
		var m, k, b []byte
		var l int

		// Fuzz the test inputs
		f.Fuzz(&m)
		f.Fuzz(&b)
		f.NumElements(KeyBytesMin, KeyBytesMax).Fuzz(&k)
		f.Fuzz(&l)

		// Scale length to allowed range
		if l < 0 {
			l = -l
		}
		l = l%(BytesMax-BytesMin) + BytesMin

		// Create a hash
		h := make([]byte, l)
		Sum(h, m, k)

		// Create the same hash with the streaming functions
		s = New(l, k)
		s.Write(m)

		// Check size
		if s.Size() != l {
			t.Error("Sum size mismatch")
		}

		// Compare hashes
		if !bytes.Equal(s.Sum(b), append(b, h...)) {
			t.Log(len(h))
			t.Errorf("Sum verification failed for: m: %x", m)
			t.FailNow()
		}
	}
}
