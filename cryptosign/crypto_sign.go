package cryptosign

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/cryptobox"
import "github.com/GoKillers/libsodium-go/support"

func CryptoSignBytes() int {
	return int(C.crypto_sign_bytes())
}

func CryptoSignSeedBytes() int {
	return int(C.crypto_sign_seedbytes())
}

func CryptoSignPublicKeyBytes() int {
	return int(C.crypto_sign_publickeybytes())
}

func CryptoSignSecretKeyBytes() int {
	return int(C.crypto_sign_secretkeybytes())
}

func CryptoSignPrimitive() string {
	return C.GoString(C.crypto_sign_primitive())
}

func CryptoSignSeedKeyPair(seed []byte) ([]byte, []byte, int) {
	support.CheckSize(seed, CryptoSignSeedBytes(), "seed")
	sk := make([]byte, CryptoSignSecretKeyBytes())
	pk := make([]byte, CryptoSignPublicKeyBytes())
	exit := int(C.crypto_sign_seed_keypair(
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]),
		(*C.uchar)(&seed[0])))

	return sk, pk, exit
}

func CryptoSignKeyPair() ([]byte, []byte, int) {
	sk := make([]byte, CryptoSignSecretKeyBytes())
	pk := make([]byte, CryptoSignPublicKeyBytes())
	exit := int(C.crypto_sign_keypair(
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0])))

	return sk, pk, exit
}

func CryptoSign(m []byte, sk []byte) ([]byte, int) {
	support.CheckSize(sk, CryptoSignSecretKeyBytes(), "secret key")
	sm := make([]byte, len(m)+CryptoSignBytes())
	var actualSmSize C.ulonglong

	exit := int(C.crypto_sign(
		(*C.uchar)(&sm[0]),
		(&actualSmSize),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&sk[0])))

	return sm[:actualSmSize], exit
}

func CryptoSignOpen(sm []byte, pk []byte) ([]byte, int) {
	support.CheckSize(pk, CryptoSignPublicKeyBytes(), "public key")
	m := make([]byte, len(sm)-CryptoSignBytes())
	var actualMSize C.ulonglong

	exit := int(C.crypto_sign_open(
		(*C.uchar)(&m[0]),
		(&actualMSize),
		(*C.uchar)(&sm[0]),
		(C.ulonglong)(len(sm)),
		(*C.uchar)(&pk[0])))

	return m[:actualMSize], exit
}

func CryptoSignDetached(m []byte, sk []byte) ([]byte, int) {
	support.CheckSize(sk, CryptoSignSecretKeyBytes(), "secret key")
	sig := make([]byte, CryptoSignBytes())
	var actualSigSize C.ulonglong

	exit := int(C.crypto_sign_detached(
		(*C.uchar)(&sig[0]),
		(&actualSigSize),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&sk[0])))

	return sig[:actualSigSize], exit
}

func CryptoSignVerifyDetached(sig []byte, m []byte, pk []byte) int {
	support.CheckSize(sig, CryptoSignBytes(), "signature")
	support.CheckSize(pk, CryptoSignPublicKeyBytes(), "public key")

	return int(C.crypto_sign_verify_detached(
		(*C.uchar)(&sig[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&pk[0])))
}

func CryptoSignEd25519PkToCurve25519(pkEd25519 []byte) ([]byte, int) {
	support.CheckSize(pkEd25519, CryptoSignPublicKeyBytes(), "public key")
	pkCurve25519 := make([]byte, cryptobox.CryptoBoxPublicKeyBytes())

	exit := int(C.crypto_sign_ed25519_pk_to_curve25519(
		(*C.uchar)(&pkCurve25519[0]),
		(*C.uchar)(&pkEd25519[0])))

	return pkCurve25519, exit
}

func CryptoSignEd25519SkToCurve25519(skEd25519 []byte) ([]byte, int) {
	support.CheckSize(skEd25519, CryptoSignSecretKeyBytes(), "secret key")
	skCurve25519 := make([]byte, cryptobox.CryptoBoxSecretKeyBytes())

	exit := int(C.crypto_sign_ed25519_sk_to_curve25519(
		(*C.uchar)(&skCurve25519[0]),
		(*C.uchar)(&skEd25519[0])))

	return skCurve25519, exit
}
