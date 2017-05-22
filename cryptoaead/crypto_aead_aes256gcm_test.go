package cryptoaead

import (
	"testing"
	"bytes"
	"github.com/google/gofuzz"
)

var testCount = 100000

type Test struct {
	Message    []byte
	Ad         []byte
	Key        [32]byte
	Nonce      [12]byte
	Ciphertext []byte
	Mac        []byte
}

func TestCryptoAEADAES256GCM(t *testing.T) {
	// Skip the test if unsupported on this platform
	if !CryptoAEADAES256GCMIsAvailable() {
		t.Skip("The CPU does not support this implementation of AES256GCM.")
	}

	// Test the key generation
	if len(CryptoAEADAES256GCMKeyGen()) != CryptoAEADAES256GCMKeyBytes() {
		t.Error("Generated key has the wrong length")
	}

	// Test the length of NSecBytes
	if CryptoAEADAES256GCMNSecBytes() != 0 {
		t.Errorf("CryptoAEADAES256GCMNSecBytes is %v but should be %v", CryptoAEADAES256GCMNSecBytes(), 0)
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

		// Create a key context
		ctx, err := CryptoAEADAES256GCMBeforeNM(test.Key[:])
		if err != 0 {
			t.Error("Context creation failed for %+v", test)
		}

		// Detached encryption test
		test.Ciphertext, test.Mac, err = CryptoAEADAES256GCMEncryptDetached(test.Message, test.Ad, test.Nonce[:], test.Key[:])
		if err != 0 {
			t.Errorf("Detached encryption failed for %+v", test)
		}

		// Detached encryption with context
		c, mac, err = CryptoAEADAES256GCMEncryptDetachedAfterNM(test.Message, test.Ad, test.Nonce[:], ctx)
		if err != 0 || !bytes.Equal(c, test.Ciphertext) || !bytes.Equal(mac, test.Mac) {
			t.Errorf("Detached encryption with context failed for %+v", test)
		}

		// Encryption test
		ec, err = CryptoAEADAES256GCMEncrypt(test.Message, test.Ad, test.Nonce[:], test.Key[:])
		if err != 0 || !bytes.Equal(ec, append(test.Ciphertext, test.Mac...)) {
			t.Errorf("Encryption failed for %+v", test)
		}

		// Encryption with context
		ec, err = CryptoAEADAES256GCMEncryptAfterNM(test.Message, test.Ad, test.Nonce[:], ctx)
		if err != 0 || !bytes.Equal(ec, append(test.Ciphertext, test.Mac...)) {
			t.Errorf("Encryption with context failed for %+v", test)
		}

		// Detached decryption test
		m, err = CryptoAEADAES256GCMDecryptDetached(c, mac, test.Ad, test.Nonce[:], test.Key[:])
		if err != 0 || !bytes.Equal(m, test.Message) {
			t.Errorf("Detached decryption failed for %+v", test)
		}

		// Detached decryption with context test
		m, err = CryptoAEADAES256GCMDecryptDetachedAfterNM(c, mac, test.Ad, test.Nonce[:], ctx)
		if err != 0 || !bytes.Equal(m, test.Message) {
			t.Errorf("Detached decryption with context failed for %+v", test)
		}

		// Decryption test
		m, err = CryptoAEADAES256GCMDecrypt(ec, test.Ad, test.Nonce[:], test.Key[:])
		if err != 0 || !bytes.Equal(m, test.Message) {
			t.Errorf("Decryption failed for %+v", test)
		}

		// Decryption with context test
		m, err = CryptoAEADAES256GCMDecryptAfterNM(ec, test.Ad, test.Nonce[:], ctx)
		if err != 0 || !bytes.Equal(m, test.Message) {
			t.Errorf("Decryption with context failed for %+v", test)
		}
	}
	t.Logf("Completed %v tests", testCount)
}
