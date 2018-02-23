// Package box contains the libsodium bindings for public-key authenticated encryption.
package box

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"

// Lengths of various arguments.
const (
	SeedBytes      = C.crypto_box_SEEDBYTES      // Required size of a keypair seed.
	PublicKeyBytes = C.crypto_box_PUBLICKEYBYTES // Size of a public key.
	SecretKeyBytes = C.crypto_box_SECRETKEYBYTES // Size of a secret key.
	NonceBytes     = C.crypto_box_NONCEBYTES     // Size of a nonce.
	MACBytes       = C.crypto_box_MACBYTES       // Size of an authentication tag.
	Primitive      = C.crypto_box_PRIMITIVE      // Name of the algorithm used by crypto/box.
	SharedKeyBytes = C.crypto_box_BEFORENMBYTES  // Size of a shared secret key.
	SealBytes      = C.crypto_box_SEALBYTES      // Overhead of a sealed encryption
)

// GenerateKeyFromSeed returns a keypair generated from a given seed.
func GenerateKeyFromSeed(seed *[SeedBytes]byte) (pk *[PublicKeyBytes]byte, sk *[SecretKeyBytes]byte) {
	support.NilPanic(seed == nil, "seed")

	pk = new([PublicKeyBytes]byte)
	sk = new([SecretKeyBytes]byte)

	C.crypto_box_seed_keypair(
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]),
		(*C.uchar)(&seed[0]))

	return
}

// GenerateKey returns a keypair.
func GenerateKey() (pk *[PublicKeyBytes]byte, sk *[SecretKeyBytes]byte) {
	pk = new([PublicKeyBytes]byte)
	sk = new([SecretKeyBytes]byte)

	C.crypto_box_keypair(
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))

	return
}

// Precompute generates a shared key from a recipients public key `pk` and a sender's secret key `sk`.
func Precompute(pk *[PublicKeyBytes]byte, sk *[SecretKeyBytes]byte) (k *[SharedKeyBytes]byte) {
	support.NilPanic(pk == nil, "public key")
	support.NilPanic(sk == nil, "secret key")

	k = new([SharedKeyBytes]byte)

	C.crypto_box_beforenm(
		(*C.uchar)(&k[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))

	return
}

// Seal encrypts a message `m` using nonce `n`, public key `pk` and secret key `sk`.
// Returns a ciphertext.
func Seal(m []byte, n *[NonceBytes]byte, pk *[PublicKeyBytes]byte, sk *[SecretKeyBytes]byte) (c []byte) {
	support.NilPanic(n == nil, "nonce")
	support.NilPanic(pk == nil, "public key")
	support.NilPanic(sk == nil, "secret key")

	c = make([]byte, len(m)+MACBytes)

	C.crypto_box_easy(
		(*C.uchar)(&c[0]),
		(*C.uchar)(support.BytePointer(m)),
		C.ulonglong(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))

	return
}

// Open decrypts a ciphertext `c` using nonce `n`, public key `pk` and secret key `sk`.
// Returns the decrypted message and an error indicating decryption or verification failure.
func Open(c []byte, n *[NonceBytes]byte, pk *[PublicKeyBytes]byte, sk *[SecretKeyBytes]byte) (m []byte, err error) {
	support.CheckSizeMin(c, MACBytes, "ciphertext")
	support.NilPanic(n == nil, "nonce")
	support.NilPanic(pk == nil, "public key")
	support.NilPanic(sk == nil, "secret key")

	m = make([]byte, len(c)-MACBytes)

	exit := C.crypto_box_open_easy(
		(*C.uchar)(support.BytePointer(m)),
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
func SealAfterPrecomputation(m []byte, n *[NonceBytes]byte, k *[SharedKeyBytes]byte) (c []byte) {
	support.NilPanic(n == nil, "nonce")
	support.NilPanic(k == nil, "shared key")

	c = make([]byte, len(m)+MACBytes)

	C.crypto_box_easy_afternm(
		(*C.uchar)(&c[0]),
		(*C.uchar)(support.BytePointer(m)),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))

	return
}

// OpenAfterPrecomputation decrypts a ciphertext `c` using nonce `n` from a shared secret key `k`.
// Returns the decrypted message and an error indicating decryption or verification failure.
func OpenAfterPrecomputation(c []byte, n *[NonceBytes]byte, k *[SharedKeyBytes]byte) (m []byte, err error) {
	support.CheckSizeMin(c, MACBytes, "ciphertext")
	support.NilPanic(n == nil, "nonce")
	support.NilPanic(k == nil, "shared key")

	m = make([]byte, len(c)-MACBytes)

	exit := C.crypto_box_open_easy_afternm(
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

// SealDetached encrypts a message `m` using nonce `n`, public key `pk` and secret key `sk`.
// Returns a ciphertext and an authentication tag.
func SealDetached(m []byte, n *[NonceBytes]byte, pk *[PublicKeyBytes]byte, sk *[SecretKeyBytes]byte) (c []byte, mac *[MACBytes]byte) {
	support.NilPanic(n == nil, "nonce")
	support.NilPanic(pk == nil, "public key")
	support.NilPanic(sk == nil, "secret key")

	c = make([]byte, len(m))
	mac = new([MACBytes]byte)

	C.crypto_box_detached(
		(*C.uchar)(support.BytePointer(c)),
		(*C.uchar)(&mac[0]),
		(*C.uchar)(support.BytePointer(m)),
		C.ulonglong(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))

	return
}

// OpenDetached decrypts a ciphertext `c` using nonce `n`, public key `pk` and secret key `sk`.
// Returns the decrypted message and an error indicating decryption or verification failure.
func OpenDetached(c []byte, mac *[MACBytes]byte, n *[NonceBytes]byte, pk *[PublicKeyBytes]byte, sk *[SecretKeyBytes]byte) (m []byte, err error) {
	support.NilPanic(mac == nil, "mac")
	support.NilPanic(n == nil, "nonce")
	support.NilPanic(pk == nil, "public key")
	support.NilPanic(sk == nil, "secret key")

	m = make([]byte, len(c))

	exit := C.crypto_box_open_detached(
		(*C.uchar)(support.BytePointer(m)),
		(*C.uchar)(support.BytePointer(c)),
		(*C.uchar)(&mac[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))

	if exit != 0 {
		err = &support.VerificationError{}
	}

	return
}

// SealDetachedAfterPrecomputation encrypts a message `m` with nonce `n` from a shared secret key `k`.
// Returns a ciphertext and an authentication tag.
func SealDetachedAfterPrecomputation(m []byte, n *[NonceBytes]byte, k *[SharedKeyBytes]byte) (c []byte, mac *[MACBytes]byte) {
	support.NilPanic(n == nil, "nonce")
	support.NilPanic(k == nil, "shared key")

	c = make([]byte, len(m))
	mac = new([MACBytes]byte)

	C.crypto_box_detached_afternm(
		(*C.uchar)(support.BytePointer(c)),
		(*C.uchar)(&mac[0]),
		(*C.uchar)(support.BytePointer(m)),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))

	return
}

// OpenDetachedAfterPrecomputation decrypts a ciphertext `c` using nonce `n` from a shared secret key `k`.
// Returns the decrypted message and an error indicating decryption or verification failure.
func OpenDetachedAfterPrecomputation(c []byte, mac *[MACBytes]byte, n *[NonceBytes]byte, k *[SharedKeyBytes]byte) (m []byte, err error) {
	support.NilPanic(mac == nil, "mac")
	support.NilPanic(n == nil, "nonce")
	support.NilPanic(k == nil, "shared key")

	m = make([]byte, len(c))

	exit := C.crypto_box_open_detached_afternm(
		(*C.uchar)(support.BytePointer(m)),
		(*C.uchar)(support.BytePointer(c)),
		(*C.uchar)(&mac[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))

	if exit != 0 {
		err = &support.VerificationError{}
	}

	return
}

// SealAnonymous encrypts a message `m` for a public key `pk` without information about the sender.
// Returns the encrypted message.
func SealAnonymous(m []byte, pk *[PublicKeyBytes]byte) (c []byte) {
	support.NilPanic(pk == nil, "public key")

	c = make([]byte, len(m)+SealBytes)

	C.crypto_box_seal(
		(*C.uchar)(&c[0]),
		(*C.uchar)(support.BytePointer(m)),
		C.ulonglong(len(m)),
		(*C.uchar)(&pk[0]))

	return
}

// OpenAnonymous decrypts a message `m` with public key `pk` and secret key `sk`.
// Returns the decrypted message and an error indicating decryption or verification failure.
func OpenAnonymous(c []byte, pk *[PublicKeyBytes]byte, sk *[SecretKeyBytes]byte) (m []byte, err error) {
	support.CheckSizeMin(c, SealBytes, "ciphertext")
	support.NilPanic(pk == nil, "public key")
	support.NilPanic(sk == nil, "secret key")

	m = make([]byte, len(c)-SealBytes)

	exit := C.crypto_box_seal_open(
		(*C.uchar)(support.BytePointer(m)),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))

	if exit != 0 {
		err = &support.VerificationError{}
	}

	return
}
