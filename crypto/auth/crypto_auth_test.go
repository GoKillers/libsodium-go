package auth

import (
	"github.com/google/gofuzz"
	"testing"
)

var testCount = 100000

func TestAuth(t *testing.T) {
	// Check primitive
	if Primitive != "hmacsha512256" {
		t.Errorf("Unexpected primitive: %s", Primitive)
	}

	// Test the key generation
	if *GenerateKey() == (Key{}) {
		t.Error("Generated key is zero")
	}

	// Fuzzing
	f := fuzz.New()

	// Run tests
	for i := 0; i < testCount; i++ {
		var m []byte
		var k Key

		// Fuzz the test inputs
		f.Fuzz(&m)
		f.Fuzz(&k)

		// Create a tag
		h := New(m, &k)

		// CheckMAC the tag for correct info
		if CheckMAC(m, h, &k) != nil {
			t.Errorf("Verification failed for: h: %x, m: %x, k: %x", h, m, k)
		}

		// CheckMAC the tag for incorrect info
		m = append(m, 0)
		if CheckMAC(m, h, &k) == nil {
			t.Errorf("Verification unexpectedly succeeded for: h: %x, m: %x, k: %x", h, m, k)
		}
	}
}
