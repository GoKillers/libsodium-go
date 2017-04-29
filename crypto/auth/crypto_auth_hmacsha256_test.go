package auth

import (
	"bytes"
	"github.com/GoKillers/libsodium-go/crypto/auth/hmacsha256"
	"github.com/google/gofuzz"
	"testing"
)

func TestHMACSHA256(t *testing.T) {
	// Test the key generation
	if *hmacsha256.GenerateKey() == (hmacsha256.Key{}) {
		t.Error("Generated key is zero")
	}

	// Check properties of HMAC
	h := NewHMACSHA256(nil)

	if h.Size() != hmacsha256.Bytes {
		t.Errorf("Incorrect size for hash: %#v", h)
	}

	if h.BlockSize() != 64 {
		t.Errorf("Incorrect size for hash: %#v", h)
	}

	// Fuzzing
	f := fuzz.New()

	// Run tests
	for i := 0; i < testCount; i++ {
		var m, sk []byte
		var k hmacsha256.Key

		// Fuzz the test inputs
		f.Fuzz(&m)
		f.Fuzz(&sk)
		f.Fuzz(&k)

		// Create a tag
		h := hmacsha256.New(m, &k)

		// CheckMAC the tag
		if hmacsha256.CheckMAC(m, h, &k) != nil {
			t.Errorf("Verification failed for: h: %x, m: %x, k: %x", h, m, k)
		}

		// Authenticate the same with the prepared functions
		hmac := NewHMACSHA256(k[:])
		hmac.Write(m)
		sh := hmac.Sum(nil)

		if !bytes.Equal(sh, h[:]) {
			t.Errorf("Prepared verification failed for: h: %x, m: %x, k: %x", h, m, k)
		}

		// Authenticate with streaming functions and an arbitrary length key
		hmac = NewHMACSHA256(sk)
		hmac.Write(m)
		sh = hmac.Sum(nil)

		// CheckMAC the tag
		if len(sh) != hmacsha256.Bytes {
			t.Errorf("Prepared verification failed for: h: %x, m: %x, k: %x", h, m, k)
		}
	}
}
