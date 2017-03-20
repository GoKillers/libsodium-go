package cryptoaead

import (
	"testing"
	"bytes"
	"github.com/google/gofuzz"
)

var testCount = 1000000

type Test struct {
	Message    []byte
	Ad         []byte
	Key        [32]byte
	Nonce      [12]byte
}

func TestCryptoAEADAES256GCM(t *testing.T) {
	// Skip the test if unsupported on this platform
	if !CryptoAEADAES256GCMIsAvailable() {
		t.Skip()
	}

	// Test the key generation
	if len(CryptoAEADAES256GCMKeyGen()) != CryptoAEADAES256GCMKeyBytes() {
		t.Error("Generated key has the wrong length")
	}

	// Fuzzing
	f := fuzz.New()

	// Run tests
	for i := 0; i < testCount; i++ {
		var c, m, ec, mac []byte
		var err int
		var test Test

		// Fuzz the test struct
		f.Fuzz(&test)

		// Detached encryption test
		c, mac, err = CryptoAEADAES256GCMEncryptDetached(test.Message, test.Ad, test.Nonce[:], test.Key[:])
		if err != 0 {
			t.Errorf("Detached encryption failed for %+v", test)
			t.FailNow()
		}

		// Encryption test
		ec, err = CryptoAEADAES256GCMEncrypt(test.Message, test.Ad, test.Nonce[:], test.Key[:])
		if err != 0 || !bytes.Equal(ec, append(c, mac...)) {
			t.Errorf("Encryption failed for %+v", test)
			t.FailNow()
		}

		// Detached decryption test
		m, err = CryptoAEADAES256GCMDecryptDetached(c, mac, test.Ad, test.Nonce[:], test.Key[:])
		if err != 0 || !bytes.Equal(m, test.Message) {
			t.Errorf("Detached decryption failed for %+v", test)
			t.FailNow()
		}

		// Decryption test
		m, err = CryptoAEADAES256GCMDecrypt(ec, test.Ad, test.Nonce[:], test.Key[:])
		if err != 0 || !bytes.Equal(m, test.Message) {
			t.Errorf("Decryption failed for %+v", test)
			t.FailNow()
		}
	}
	t.Logf("Completed %v tests", testCount)
}
