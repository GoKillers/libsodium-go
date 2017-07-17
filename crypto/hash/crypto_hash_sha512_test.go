package hash

import (
	"bytes"
	"github.com/google/gofuzz"
	"testing"
)

func TestSHA512(t *testing.T) {
	// Fuzzing
	f := fuzz.New().NilChance(0.01).NumElements(1, 1024)

	// Check size
	s := NewSHA512()
	if s.Size() != SHA512Bytes {
		t.Error("SHA512 size mismatch")
	}

	// Check block size
	if s.BlockSize() != 1 {
		t.Error("SHA512 block size incorrect")
	}

	// Run tests
	for i := 0; i < testCount; i++ {
		var m, sk, b []byte

		// Fuzz the test inputs
		f.Fuzz(&m)
		f.Fuzz(&sk)
		f.Fuzz(&b)

		// Create a hash
		h := SumSHA512(m)

		// Create the same hash with the streaming functions
		s.Reset()
		s.Write(m)
		sh := s.Sum(b)

		if !bytes.Equal(sh, append(b, h...)) {
			t.Log(len(h))
			t.Errorf("SHA512 streaming verification failed for: m: %x", m)
			t.FailNow()
		}
	}
}
