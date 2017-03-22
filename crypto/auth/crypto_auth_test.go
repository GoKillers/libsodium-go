package auth

import (
	"testing"
	"github.com/google/gofuzz"
)

var testCount = 100000

func Test(t *testing.T) {
	// Check primitive
	if Primitive() != "hmacsha512256" {
		t.Error("Incorrect primitive")
	}

	// Test the key generation
	if len(KeyGen()) != KeyBytes() {
		t.Error("Generated key has the wrong length")
	}

	// Fuzzing
	f := fuzz.New()

	// Run tests
	for i := 0; i < testCount; i++ {
		var m []byte
		var k [32]byte

		// Fuzz the test inputs
		f.Fuzz(&m)
		f.Fuzz(&k)

		// Create a tag
		h := Auth(m, k[:])

		// Verify the tag
		if !Verify(h, m, k[:]) {
			t.Errorf("Verification failed for: h: %x, m: %x, k: %x", h, m, k)
		}
	}
}
