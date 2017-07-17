package generichash

import (
	"bytes"
	"github.com/google/gofuzz"
	"testing"
)

func TestBlake2b(t *testing.T) {
	// Check default hash size
	if Blake2bBytes != 32 {
		t.Errorf("Unexpected hash length: %v", Blake2bBytes)
	}

	// Test the key generation
	if bytes.Equal(GenerateKeyBlake2b(), make([]byte, Blake2bKeyBytes)) {
		t.Error("Generated key is zero")
	}

	// Fuzzing
	f := fuzz.New().NilChance(0.01).NumElements(1, 1024)

	// Check size
	s := New(BytesMin, nil)

	// Check block size
	if s.BlockSize() != 1 {
		t.Error("Sum block size incorrect")
	}

	// Run tests
	for i := 0; i < testCount; i++ {
		var m, k, b []byte
		var st [Blake2bSaltBytes]byte
		var p [Blake2bPersonalBytes]byte
		var l int

		// Fuzz the test inputs
		f.Fuzz(&m)
		f.Fuzz(&b)
		f.NumElements(KeyBytesMin, KeyBytesMax).Fuzz(&k)
		f.Fuzz(&st)
		f.Fuzz(&p)
		f.Fuzz(&l)

		// Scale length to allowed range
		if l < 0 {
			l = -l
		}
		l = l%(BytesMax-BytesMin) + BytesMin

		// Create a hash
		h := make([]byte, l)
		SumBlake2b(h, m, k)

		// Create the same hash with the streaming functions
		s = NewBlake2b(l, k)
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

		// Create a salted/personalised hash
		SumBlake2bSaltPersonal(h, m, k, st[:], p[:])

		// Create the same hash with the streaming functions
		s = NewBlake2bSaltPersonal(l, k, st[:], p[:])
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
