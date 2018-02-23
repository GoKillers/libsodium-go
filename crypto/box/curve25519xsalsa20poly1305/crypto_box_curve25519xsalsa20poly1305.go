// Package curve25519xsalsa20poly1305 contains the libsodium bindings
// for public-key authenticated encryption using Curve25519-XSalsa20-Poly1305.
package curve25519xsalsa20poly1305

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"

// Lengths of various arguments.
const (
	SeedBytes      = C.crypto_box_curve25519xsalsa20poly1305_SEEDBYTES      // Required size of a keypair seed.
	PublicKeyBytes = C.crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES // Size of a public key.
	SecretKeyBytes = C.crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES // Size of a secret key.
	NonceBytes     = C.crypto_box_curve25519xsalsa20poly1305_NONCEBYTES     // Size of a nonce.
	MACBytes       = C.crypto_box_curve25519xsalsa20poly1305_MACBYTES       // Size of an authentication tag.
	SharedKeyBytes = C.crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES  // Size of a shared secret key.
	ZeroBytes      = C.crypto_box_ZEROBYTES                                 // Size of the zero padding of the message.
	BoxZeroBytes   = C.crypto_box_BOXZEROBYTES                              // Size of NaCl box / ciphertext
)

// GenerateKeysFromSeed returns a keypair generated from a given seed.
func GenerateKeysFromSeed(seed []byte) (pk *[PublicKeyBytes]byte, sk *[SecretKeyBytes]byte) {
	support.CheckSize(seed, SeedBytes, "seed")

	pk = new([PublicKeyBytes]byte)
	sk = new([SecretKeyBytes]byte)

	C.crypto_box_curve25519xsalsa20poly1305_seed_keypair(
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]),
		(*C.uchar)(&seed[0]))

	return
}

// GenerateKeys returns a keypair.
func GenerateKeys() (pk *[PublicKeyBytes]byte, sk *[SecretKeyBytes]byte) {
	pk = new([PublicKeyBytes]byte)
	sk = new([SecretKeyBytes]byte)

	C.crypto_box_curve25519xsalsa20poly1305_keypair(
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))

	return
}

// Precompute generates a shared key from a recipients public key `pk` and a sender's secret key `sk`.
func Precompute(pk *[PublicKeyBytes]byte, sk *[SecretKeyBytes]byte) (k *[SharedKeyBytes]byte) {
	support.NilPanic(pk == nil, "public key")
	support.NilPanic(sk == nil, "secret key")

	k = new([SharedKeyBytes]byte)

	C.crypto_box_curve25519xsalsa20poly1305_beforenm(
		(*C.uchar)(&k[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))

	return
}

// Seal encrypts a message `m` using nonce `n`, public key `pk` and secret key `sk`.
// Returns the encrypted message.
// Note: message `m` requires `ZeroBytes` of padding on the front.
func Seal(m, n []byte, pk *[PublicKeyBytes]byte, sk *[SecretKeyBytes]byte) (c []byte) {
	support.CheckSizeMin(m, ZeroBytes, "message with padding")
	support.CheckSize(n, NonceBytes, "nonce")
	support.NilPanic(pk == nil, "public key")
	support.NilPanic(sk == nil, "secret key")

	c = make([]byte, len(m))

	C.crypto_box_curve25519xsalsa20poly1305(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		C.ulonglong(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))

	return
}

// Open decrypts a ciphertext `c` using nonce `n`, public key `pk` and secret key `sk`.
// Returns the decrypted message and an error indicating decryption or verification failure.
// Note: ciphertext `c` requires `BoxZeroBytes` padding on the front.
func Open(c, n []byte, pk *[PublicKeyBytes]byte, sk *[SecretKeyBytes]byte) (m []byte, err error) {
	support.CheckSizeMin(c, ZeroBytes, "ciphertext with padding")
	support.CheckSize(n, NonceBytes, "nonce")
	support.NilPanic(pk == nil, "public key")
	support.NilPanic(sk == nil, "secret key")

	m = make([]byte, len(c))

	exit := C.crypto_box_curve25519xsalsa20poly1305_open(
		(*C.uchar)(&m[0]),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))

	if exit != 0 {
		err = &support.VerificationError{}
	}

	return
}

// SealAfterPrecomputation encrypts a message `m` with nonce `n` from a shared secret key `k`.
// Returns the encrypted message.
// Note: message `m` requires `ZeroBytes` of padding on the front.
func SealAfterPrecomputation(m, n []byte, k *[SharedKeyBytes]byte) (c []byte) {
	support.CheckSizeMin(m, ZeroBytes, "message with padding")
	support.CheckSize(n, NonceBytes, "nonce")
	support.NilPanic(k == nil, "shared key")

	c = make([]byte, len(m))

	C.crypto_box_curve25519xsalsa20poly1305_afternm(
		(*C.uchar)(&c[0]),
		(*C.uchar)(support.BytePointer(m)),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))

	return
}

// OpenAfterPrecomputation decrypts a ciphertext `c` using nonce `n` from a shared secret key `k`.
// Returns the decrypted message and an error indicating decryption or verification failure.
// Note: ciphertext `c` requires `BoxZeroBytes` padding on the front.
func OpenAfterPrecomputation(c, n []byte, k *[SharedKeyBytes]byte) (m []byte, err error) {
	support.CheckSizeMin(c, ZeroBytes, "ciphertext with padding")
	support.CheckSize(n, NonceBytes, "nonce")
	support.NilPanic(k == nil, "shared key")

	m = make([]byte, len(c))

	exit := C.crypto_box_curve25519xsalsa20poly1305_open_afternm(
		(*C.uchar)(support.BytePointer(m)),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))

	if exit != 0 {
		err = &support.VerificationError{}
	}

	return
}
