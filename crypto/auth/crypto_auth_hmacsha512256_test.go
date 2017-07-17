package auth

import (
	"bytes"
	"github.com/GoKillers/libsodium-go/crypto/auth/hmacsha512256"
	"github.com/google/gofuzz"
	"testing"
)

func TestHMACSHA512256(t *testing.T) {
	// Check properties of HMAC
	h := NewHMACSHA512256(nil)

	if h.Size() != hmacsha512256.Bytes {
		t.Errorf("Incorrect size for hash: %#v", h)
	}

	if h.BlockSize() != 2*hmacsha512256.Bytes {
		t.Errorf("Incorrect size for hash: %#v", h)
	}

	// Fuzzing
	f := fuzz.New()

	// Run tests
	for i := 0; i < testCount; i++ {
		var m, sk []byte
		var k [hmacsha512256.KeyBytes]byte

		// Fuzz the test inputs
		f.Fuzz(&m)
		f.Fuzz(&sk)
		f.Fuzz(&k)

		// Create a tag
		h := hmacsha512256.New(m, &k)

		// CheckMAC the tag
		if hmacsha512256.CheckMAC(m, h, &k) != nil {
			t.Errorf("Verification failed for: h: %x, m: %x, k: %x", h, m, k)
		}

		// Authenticate the same with the prepared functions
		hmac := NewHMACSHA512256(k[:])
		hmac.Write(m)
		sh := hmac.Sum(nil)

		if !bytes.Equal(sh, h[:]) {
			t.Errorf("Prepared verification failed for: h: %x, m: %x, k: %x", h, m, k)
		}

		// Authenticate with streaming functions and an arbitrary length key
		hmac = NewHMACSHA512256(sk)
		hmac.Write(m)
		sh = hmac.Sum(nil)

		// CheckMAC the tag
		if len(sh) != hmacsha512256.Bytes {
			t.Errorf("Prepared verification failed for: h: %x, m: %x, k: %x", h, m, k)
		}
	}
}
