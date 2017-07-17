package aead

import (
	"bytes"
	"github.com/GoKillers/libsodium-go/crypto/aead/aes256gcm"
	"github.com/google/gofuzz"
	"testing"
)

var testCount = 100000

type TestData struct {
	Message []byte
	Ad      []byte
	Dst     []byte
	Key     [aes256gcm.KeyBytes]byte
	Nonce   [aes256gcm.NonceBytes]byte
}

func Test(t *testing.T) {
	// Skip the test if unsupported on this platform
	if !aes256gcm.IsAvailable() {
		t.Skip("The CPU does not support this implementation of AES256GCM.")
	}

	// Fuzzing
	f := fuzz.New()

	// Run tests
	for i := 0; i < testCount; i++ {
		var c, m, ec, mac []byte
		var err error
		var test TestData

		// Fuzz the test struct
		f.Fuzz(&test)

		// Create a key context
		ctx := NewAES256GCM(&test.Key)

		// Detached encryption test
		c, mac = ctx.SealDetached(test.Dst, test.Nonce[:], test.Message, test.Ad)

		// Check if dst was prepended
		if !bytes.Equal(c[:len(test.Dst)], test.Dst) {
			t.Error("dst was not prepended")
			t.FailNow()
		}

		// Encryption test
		ec = ctx.Seal(test.Dst, test.Nonce[:], test.Message, test.Ad)
		if !bytes.Equal(ec, append(c, mac...)) {
			t.Errorf("Encryption failed for %+v", test)
			t.FailNow()
		}

		// Detached decryption test
		m, err = ctx.OpenDetached(test.Dst, test.Nonce[:], c[len(test.Dst):], mac, test.Ad)
		if err != nil || !bytes.Equal(m[len(test.Dst):], test.Message) {
			t.Errorf("Detached decryption failed for %+v", test)
			t.FailNow()
		}

		// Check if dst was prepended
		if !bytes.Equal(m[:len(test.Dst)], test.Dst) {
			t.Error("dst was not prepended")
			t.FailNow()
		}

		// Decryption test
		m, err = ctx.Open(test.Dst, test.Nonce[:], ec[len(test.Dst):], test.Ad)
		if err != nil || !bytes.Equal(m[len(test.Dst):], test.Message) {
			t.Errorf("Decryption failed for %+v", test)
			t.FailNow()
		}

		// Failed detached decryption test
		mac = make([]byte, ctx.Overhead())
		m, err = ctx.OpenDetached(test.Dst, test.Nonce[:], c[len(test.Dst):], mac, test.Ad)
		if err == nil {
			t.Errorf("Detached decryption unexpectedly succeeded for %+v", test)
			t.FailNow()
		}

		// Failed decryption test
		copy(ec[len(test.Dst)+len(m):], mac)
		m, err = ctx.Open(test.Dst, test.Nonce[:], ec[len(test.Dst):], test.Ad)
		if err == nil {
			t.Errorf("Decryption unexpectedly succeeded for %+v", test)
			t.FailNow()
		}
	}

	t.Logf("Completed %v tests", testCount)
}
