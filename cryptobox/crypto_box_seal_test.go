package cryptobox

import "testing"

func TestCryptoBoxSeal(t *testing.T) {
	sk, pk, exit := CryptoBoxKeyPair()
	if exit != 0 {
		t.Fatalf("CryptoBoxKeyPair failed: %v", exit)
	}
	testStr := "test string 12345678901234567890123456789012345678901234567890"
	cipherText, exit := CryptoBoxSeal([]byte(testStr), pk)
	if exit != 0 {
		t.Fatalf("CryptoBoxSeal failed: %v", exit)
	}
	plaintext, exit := CryptoBoxSealOpen(cipherText, pk, sk)
	if exit != 0 {
		t.Fatalf("CryptoBoxSealOpen failed: %v", exit)
	}
	if string(plaintext) != testStr {
		t.Fatalf("Bad plaintext: %#v", plaintext)
	}
}
