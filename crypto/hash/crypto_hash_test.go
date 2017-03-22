package hash

import (
	"bytes"
	"github.com/google/gofuzz"
	"testing"
)

var testCount = 5000

func Test(t *testing.T) {
	// Check algorithm name
	if Primitive() != "sha512" {
		t.Errorf("Incorrect primitive: %s", Primitive())
	}

	// Fuzzing
	f := fuzz.New().NilChance(0.01).NumElements(1, 1024)

	// Run tests
	for i := 0; i < testCount; i++ {
		var m, sk []byte

		// Fuzz the test inputs
		f.Fuzz(&m)
		f.Fuzz(&sk)

		// Create a hash
		h := Hash(m)

		// Create the same hash with SHA512
		sh := SHA512(m)

		if !bytes.Equal(sh, h) {
			t.Errorf("Hash failed for: m: %x", m)
			t.FailNow()
		}
	}
}
