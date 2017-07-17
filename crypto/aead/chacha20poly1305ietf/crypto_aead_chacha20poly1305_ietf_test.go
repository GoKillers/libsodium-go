package chacha20poly1305ietf

import (
	"bytes"
	"github.com/google/gofuzz"
	"testing"
)

var testCount = 100000

type TestData struct {
	Message []byte
	Ad      []byte
	Key     [KeyBytes]byte
	Nonce   [NonceBytes]byte
}

func Test(t *testing.T) {
	// Test the key generation
	if *GenerateKey() == ([KeyBytes]byte{}) {
		t.Error("Generated key is zero")
	}

	// Test the length of NSecBytes
	if NSecBytes != 0 {
		t.Errorf("NSecBytes is %v but should be %v", NSecBytes, 0)
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

		// Detached encryption test
		c, mac = EncryptDetached(test.Message, test.Ad, &test.Nonce, &test.Key)

		// Encryption test
		ec = Encrypt(test.Message, test.Ad, &test.Nonce, &test.Key)
		if !bytes.Equal(ec, append(c, mac...)) {
			t.Errorf("Encryption failed for %+v", test)
			t.FailNow()
		}

		// Detached decryption test
		m, err = DecryptDetached(c, mac, test.Ad, &test.Nonce, &test.Key)
		if err != nil || !bytes.Equal(m, test.Message) {
			t.Errorf("Detached decryption failed for %+v", test)
			t.FailNow()
		}

		// Decryption test
		m, err = Decrypt(ec, test.Ad, &test.Nonce, &test.Key)
		if err != nil || !bytes.Equal(m, test.Message) {
			t.Errorf("Decryption failed for %+v", test)
			t.FailNow()
		}

		// Failed detached decryption test
		mac = make([]byte, ABytes)
		m, err = DecryptDetached(c, mac, test.Ad, &test.Nonce, &test.Key)
		if err == nil {
			t.Errorf("Detached decryption unexpectedly succeeded for %+v", test)
			t.FailNow()
		}

		// Failed decryption test
		copy(ec[len(m):], mac)
		m, err = Decrypt(ec, test.Ad, &test.Nonce, &test.Key)
		if err == nil {
			t.Errorf("Decryption unexpectedly succeeded for %+v", test)
			t.FailNow()
		}
	}
	t.Logf("Completed %v tests", testCount)
}
