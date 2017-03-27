package box

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

func TestCryptoBox(t *testing.T) {
	// Check primitive
	if Primitive != "curve25519xsalsa20poly1305" {
		t.Errorf("Unexpected primitive: %s", Primitive)
	}

	// Test if GenerateKeys creates a non-zero key
	pk, sk := GenerateKeys()
	zeroes := new([32]byte)
	if *pk == PublicKey(*zeroes) || *sk == SecretKey(*zeroes) {
		t.Error("GenerateKeys generated an all zero key.")
	}

	// Fuzzing
	f := fuzz.New().NumElements(1, 1024)

	// Run tests
	for i := 0; i < testCount; i++ {
		var test Test
		var err error
		var testMac, ciphertext []byte
		var fail bool

		// Fuzz the test struct
		f.Fuzz(&test)
		f.Fuzz(&fail)

		// Generate Keys
		pk, sk = GenerateKeysFromSeed(test.Seed[:])

		// Generate shared key
		shk := Precompute(pk, sk)

		// Detached encryption test
		ciphertext, testMac = SealDetached(test.Message, test.Nonce[:], pk, sk)

		// Detached encryption after precomputation
		c, mac := SealDetachedAfterPrecomputation(test.Message, test.Nonce[:], shk)
		if !bytes.Equal(c, ciphertext) || !bytes.Equal(mac, testMac) {
			t.Errorf("Detached encryption with shared key failed for %+v", test)
			t.FailNow()
		}

		// Encryption
		ec := Seal(test.Message, test.Nonce[:], pk, sk)
		if !bytes.Equal(ec, append(testMac, ciphertext...)) {
			t.Errorf("Encryption failed for %+v", test)
			t.FailNow()
		}

		// Encryption with shared key
		ec = SealAfterPrecomputation(test.Message, test.Nonce[:], shk)
		if !bytes.Equal(ec, append(testMac, ciphertext...)) {
			t.Errorf("Encryption with shared key failed for %+v", test)
			t.FailNow()
		}

		// NaCl encryption
		mPad := append(make([]byte, ZeroBytes), test.Message...)
		ec = NaClSeal(mPad, test.Nonce[:], pk, sk)
		ec = ec[BoxZeroBytes:]
		if !bytes.Equal(ec, append(testMac, ciphertext...)) {
			t.Errorf("NaCl encryption failed for %+v", test)
			t.FailNow()
		}

		// NaCl encryption with shared key
		ec = NaClSealAfterPrecomputation(mPad, test.Nonce[:], shk)
		ec = ec[BoxZeroBytes:]
		if !bytes.Equal(ec, append(testMac, ciphertext...)) {
			t.Errorf("NaCl encryption with shared key failed for %+v", test)
			t.FailNow()
		}

		// Test with incorrect MAC
		if fail {
			mac = make([]byte, MACBytes)
			copy(ec[len(ec)-MACBytes:], mac)
		}

		// Detached decryption test
		m, err := OpenDetached(c, mac, test.Nonce[:], pk, sk)
		if checkResult(fail, err, m, test.Message) {
			t.Errorf("Detached decryption failed for %+v", test)
			t.FailNow()
		}

		// Detached decryption with shared key test
		m, err = OpenDetachedAfterPrecomputation(c, mac, test.Nonce[:], shk)
		if checkResult(fail, err, m, test.Message) {
			t.Errorf("Detached decryption with shared key failed for %+v", test)
			t.FailNow()
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

		// NaCl decryption test
		ecPad := append(make([]byte, BoxZeroBytes), ec...)
		m, err = NaClOpen(ecPad, test.Nonce[:], pk, sk)
		m = m[ZeroBytes:]
		if checkResult(fail, err, m, test.Message) {
			t.Errorf("NaCl decryption failed for %+v", test)
			t.FailNow()
		}

		// NaCl decryption with shared key test
		m, err = NaClOpenAfterPrecomputation(ecPad, test.Nonce[:], shk)
		m = m[ZeroBytes:]
		if checkResult(fail, err, m, test.Message) {
			t.Errorf("NaCl decryption with shared key failed for %+v", test)
			t.FailNow()
		}

		// Anonymous test
		ec = SealAnonymous(test.Message, pk)

		if fail {
			copy(ec[len(ec)-MACBytes:], mac)
		}

		m, err = OpenAnonymous(ec, pk, sk)
		if checkResult(fail, err, m, test.Message) {
			t.Errorf("Anonymous decryption failed (%v) for c: %v, m: %v", err, ec, test.Message)
			t.FailNow()
		}
	}
	t.Logf("Completed %v tests", testCount)
}
