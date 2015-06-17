package nacl

// #cgo CFLAGS: -I/usr/local/include/sodium
// #cgo LDFLAGS: /usr/local/lib/libsodium.a
// #include <stdio.h>
// #include <sodium.h>
import "C"

func CryptoBoxSeedBytes() int {
	return int(C.crypto_box_seedbytes())
}

func CryptoBoxPublicKeyBytes() int {
	return int(C.crypto_box_publickeybytes())
}

func CryptoBoxSecretKeyBytes() int {
	return int(C.crypto_box_secretkeybytes())
}

func CryptoBoxNonceBytes() int {
	return int(C.crypto_box_noncebytes())
}

func CryptoBoxMacBytes() int {
	return int(C.crypto_box_macbytes())
}

func CryptoBoxPrimitive() string {
	return C.GoString(C.crypto_box_primitive())
}

func CryptoBoxBeforeNmBytes() int {
	return int(C.crypto_box_beforenmbytes())
}

func CryptoBoxSealBytes() int {
	return int(C.crypto_box_sealbytes())
}

func CryptoBoxZeroBytes() int {
	return int(C.crypto_box_zerobytes())
}

func CryptoBoxBoxZeroBytes() int {
	return int(C.crypto_box_boxzerobytes())
}

func CryptoBoxSeedKeyPair(seed []byte) ([]byte, []byte, int) {
	checkSize(seed, CryptoBoxSeedBytes(), "seed")
	sk := make([]byte, CryptoBoxSecretKeyBytes())
	pk := make([]byte, CryptoBoxPublicKeyBytes())
	exit := int(C.crypto_box_seed_keypair(
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]),
		(*C.uchar)(&seed[0])))

	return sk, pk, exit
}

func CryptoBoxKeyPair() ([]byte, []byte, int) {
	sk := make([]byte, CryptoBoxSecretKeyBytes())
	pk := make([]byte, CryptoBoxPublicKeyBytes())
	exit := int(C.crypto_box_keypair(
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0])))

	return sk, pk, exit
}

func CryptoBoxEasy(m []byte, n []byte, pk []byte, sk []byte) ([]byte, int) {
	checkSize(n, CryptoBoxNonceBytes(), "nonce")
	checkSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	checkSize(sk, CryptoBoxSecretKeyBytes(), "secret key")
	c := make([]byte, len(m)+CryptoBoxMacBytes())
	exit := int(C.crypto_box_easy(
		(*C.uchar)(&c[0]),
		(*C.uchar)(m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0])))

	return c, exit
}

func CryptoBoxOpenEasy(c []byte, n []byte, pk []byte, sk []byte) ([]byte, int) {
	checkSize(n, CryptoBoxNonceBytes(), "nonce")
	checkSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	checkSize(sk, CryptoBoxSecretKeyBytes(), "secret key")
	m := make([]byte, len(c)-CryptoBoxMacBytes())
	exit := int(C.crypto_box_easy(
		(*C.uchar)(m[0]),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0])))

	return m, exit
}

func CryptoBoxDetached(mac []byte, m []byte, n[] byte, pk []byte, sk []byte) ([]byte, int) {
	checkSize(mac, CryptoBoxMacBytes(), "mac")
	checkSize(n, CryptoBoxNonceBytes(), "nonce")
	checkSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	checkSize(sk, CryptoBoxSecretKeyBytes(), "sender's secret key")
	c := make([]byte, len(m)+CryptoBoxMacBytes())
	exit := int(C.crypto_box_detached(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&mac[0])
		(*C.uchar)(m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0])))

	return c, exit
}

func CryptoBoxOpenDetached(c []byte, mac []byte, n[] byte, pk []byte, sk []byte) ([]byte, int) {
	checkSize(mac, CryptoBoxMacBytes(), "mac")
	checkSize(n, CryptoBoxNonceBytes(), "nonce")
	checkSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	checkSize(sk, CryptoBoxSecretKeyBytes(), "secret key")
	m := make([]byte, len(c)-CryptoBoxMacBytes())
	exit := int(C.crypto_box_detached(
		(*C.uchar)(&m[0])
		(*C.uchar)(&c[0]),
		(*C.uchar)(&mac[0])
		(C.ulonglong)(len(c))
		(*C.uchar)(&n[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0])))

	return m, exit
}

func CryptoBoxBeforeNm(pk []byte, sk []byte) ([]byte, int) {
	checkSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	checkSize(sk, CryptoBoxSecretKeyBytes(), "sender's secret key")
	k := make([]byte, CryptoBoxBeforeNmBytes())
	exit := int(C.crypto_box_beforenm(
		(*C.uchar)(&k[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0])))

	return k, exit
}

func CryptoBoxEasyAfterNm(m []byte, n []byte, k []byte) ([]byte, int) {
	checkSize(n, CryptoBoxNonceBytes(), "nonce")
	checkSize(k, CryptoBoxBeforeNmBytes(), "shared secret key")
	c:= make([]byte, len(m)+CryptoBoxMacBytes())
	exit := int(C.crypto_box_easy_afternm(
		(*C.uchar)(&c[0]),
		(*C.uchar)(m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0])))

	return c, exit
}

func CryptoBoxOpenEasyAfterNm(c []byte, n []byte, k []byte) ([]byte, int) {
	checkSize(n, CryptoBoxNonceBytes(), "nonce")
	checkSize(k, CryptoBoxBeforeNmBytes(), "shared secret key")
	m := make([]byte, len(c)-CryptoBoxMacBytes())
	exit := int(C.crypto_box_open_easy_afternm(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0])))

	return m, exit
}

func CryptoBoxDetachedAfterNm(mac []byte, m []byte, n []byte, k []byte) ([]byte, int) {
	checkSize(mac, CryptoBoxMacBytes(), "mac")
	checkSize(n, CryptoBoxNonceBytes(), "nonce")
	checkSize(k, CryptoBoxBeforeNmBytes(), "shared secret key")
	c := make([]byte, len(m)+CryptoBoxMacBytes())
	exit := int(C.crypto_box_detached_afternm(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&mac[0]),
		(*C.uchar)(m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0])))

	return c, exit
}

func CryptoBoxOpenDetachedAfterNm(c []byte, mac []byte, n []byte, k []byte) ([]byte, int) {
	checkSize(mac, CryptoBoxMacBytes(), "mac")
	checkSize(n, CryptoBoxNonceBytes(), "nonce")
	checkSize(k, CryptoBoxBeforeNmBytes(), "shared secret key")
	m := make([]byte, len(c)-CryptoBoxMacBytes())
	exit := int(C.crypto_box_open_detached_afternm(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&c[0]),
		(*C.uchar)(&mac[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0])))

	return m, exit
}

func CryptoBoxSeal(m []byte, pk []byte) ([]byte, int) ([]byte, int) {
	checkSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	c := make([]byte, len(c)+CryptoBoxMacBytes())
	exit := int(C.crypto_box_seal(
		(*C.uchar)(&c[0]),
		(*C.uchar)(m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&pk[0])))

	return c, exit
}

func CryptoBoxSealOpen(c []byte, pk []byte, sk []byte) ([]byte, int){
	checkSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	checkSize(sk, CryptoBoxSecretKeyBytes(), "secret key")
	m := make([]byte, len(c)-CryptoBoxMacBytes())
	exit := int(C.crypto_box_seal_open(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0])))

	return m, exit
}

func CryptoBox(m []byte, n []byte, pk []byte, sk []byte) ([]byte, int) {
	checkSize(n, CryptoBoxNonceBytes(), "nonce")
	checkSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	checkSize(sk, CryptoBoxSecretKeyBytes(), "sender's secret key")
	c := make([]byte, len(m))
	exit := int(C.crypto_box(
		(*C.uchar)(&c[0]),
		(*C.uchar)(m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0])))

	return c, exit
}

func CryptoBoxOpen(c []byte, n []byte, pk []byte, sk []byte) ([]byte, int) {
	checkSize(n, CryptoBoxNonceBytes(), "nonce")
	checkSize(pk, CryptoBoxPublicKeyBytes(), "public key")
	checkSize(sk, CryptoBoxPublicKeyBytes(), "secret key")
	m := make([]byte, len(c))
	exit := int(C.crypto_box_open(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0])))

	return m, exit
}

func CryptoBoxAfterNm(m []byte, n []byte, k []byte) ([]byte, int) {
	checkSize(n, CryptoBoxNonceBytes(), "nonce")
	checkSize(k, CryptoBoxBeforeNmBytes(), "shared secret key")
	c := make([]byte, len(m))
	exit := int(C.crypto_box_afternm(
		(*C.uchar)(&c[0]),
		(*C.uchar)(m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0])))

	return c, exit
}

func CryptoBoxOpenAfteNm(c []byte, n []byte, k []byte) ([]byte, int) {
	checkSize(n, CryptoBoxNonceBytes(), "nonce")
	checkSize(k, CryptoBoxBeforeNmBytes(), "shared secret key")
	m := make([]byte, len(c))
	exit := int(C.crypto_box_afternm(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0])))

	return m, exit
}

func checkSize(buf []byte, expected int, descrip string) {
	if len(buf) != expected {
		panic(fmt.Sprintf("Incorrect %s buffer size, expected (%d), got (%d).", descrip, expected, len(buf)))
	}
}
