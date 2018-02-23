package curve25519xsalsa20poly1305

import (
	"bytes"
	"github.com/google/gofuzz"
	"testing"
)

var testCount = 5000

type Test struct {
	Message []byte
	Nonce   [NonceBytes]byte
	Seed    [SeedBytes]byte
}

func checkResult(fail bool, err error, a, b []byte) bool {
	if fail {
		return err == nil
	}
	return err != nil || !bytes.Equal(a, b)
}

func TestCryptoBoxSalsa(t *testing.T) {
	// Test if GenerateKeysFromSeed
	pk, sk := GenerateKeys()
	zeroes := new([PublicKeyBytes]byte)
	if *pk == *zeroes || *sk == *zeroes {
		t.Error("GenerateKeys generated an all zero key.")
	}

	// Fuzzing
	f := fuzz.New().NumElements(1, 1024)

	// Run tests
	for i := 0; i < testCount; i++ {
		var test Test
		var err error
		var m, ciphertext []byte
		var fail bool

		// Fuzz the test struct
		f.Fuzz(&test)
		f.Fuzz(&fail)

		// Provide the required padding
		test.Message = append(make([]byte, ZeroBytes), test.Message...)

		// Generate Keys
		pk, sk = GenerateKeysFromSeed(test.Seed[:])

		// Generate shared key
		shk := Precompute(pk, sk)

		// Encryption
		ciphertext = Seal(test.Message, test.Nonce[:], pk, sk)

		// Encryption with context
		ec := SealAfterPrecomputation(test.Message, test.Nonce[:], shk)
		if !bytes.Equal(ec, ciphertext) {
			t.Errorf("Encryption with shared key failed for %+v:", test)
			t.FailNow()
		}

		// Test with incorrect MAC
		if fail {
			copy(ec[len(ec)-MACBytes:], make([]byte, MACBytes))
		}

		// Decryption test
		m, err = Open(ec, test.Nonce[:], pk, sk)
		if checkResult(fail, err, m, test.Message) {
			t.Errorf("Decryption failed for %+v", test)
			t.FailNow()
		}

		// Decryption with shared key test
		m, err = OpenAfterPrecomputation(ec, test.Nonce[:], shk)
		if checkResult(fail, err, m, test.Message) {
			t.Errorf("Decryption with shared key failed for %+v", test)
			t.FailNow()
		}
	}
	t.Logf("Completed %v tests", testCount)
}
