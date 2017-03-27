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

// PublicKey represents a public key.
type PublicKey [PublicKeyBytes]byte

// SecretKey represents a secret (private) key.
type SecretKey [SecretKeyBytes]byte

// SharedKey represents a shared secret key generated from a public/secret key pair.
type SharedKey [SharedKeyBytes]byte

// GenerateKeysFromSeed returns a keypair generated from a given seed.
func GenerateKeysFromSeed(seed []byte) (pk *PublicKey, sk *SecretKey) {
	support.CheckSize(seed, SeedBytes, "seed")

	pk = new(PublicKey)
	sk = new(SecretKey)

	C.crypto_box_seed_keypair(
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]),
		(*C.uchar)(&seed[0]))

	return
}

// GenerateKeys returns a keypair.
func GenerateKeys() (pk *PublicKey, sk *SecretKey) {
	pk = new(PublicKey)
	sk = new(SecretKey)

	C.crypto_box_keypair(
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))

	return
}

// Precompute generates a shared key from a recipients public key `pk` and a sender's secret key `sk`.
func Precompute(pk *PublicKey, sk *SecretKey) (k *SharedKey) {
	support.NilPanic(pk == nil, "public key")
	support.NilPanic(sk == nil, "secret key")

	k = new(SharedKey)

	C.crypto_box_beforenm(
		(*C.uchar)(&k[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))

	return
}

// Seal encrypts a message `m` using nonce `n`, public key `pk` and secret key `sk`.
// Returns a ciphertext and a boolean indicating successful encryption.
func Seal(m, n []byte, pk *PublicKey, sk *SecretKey) (c []byte) {
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
// Returns the decrypted message and a boolean indicating successful decryption and verification.
func Open(c, n []byte, pk *PublicKey, sk *SecretKey) (m []byte, err error) {
	support.CheckSizeMin(c, MACBytes, "ciphertext")
	support.CheckSize(n, NonceBytes, "nonce")
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
// Returns the decrypted message and a boolean indicating successful encryption.
func SealAfterPrecomputation(m, n []byte, k *SharedKey) (c []byte) {
	support.CheckSize(n, NonceBytes, "nonce")
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
// Returns the decrypted message and a boolean indicating successful decryption and verification.
func OpenAfterPrecomputation(c, n []byte, k *SharedKey) (m []byte, err error) {
	support.CheckSizeMin(c, MACBytes, "ciphertext")
	support.CheckSize(n, NonceBytes, "nonce")
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
// Returns a ciphertext, an authentication tag and a boolean indicating successful encryption.
func SealDetached(m, n []byte, pk *PublicKey, sk *SecretKey) (c, mac []byte) {
	support.CheckSize(n, NonceBytes, "nonce")
	support.NilPanic(pk == nil, "public key")
	support.NilPanic(sk == nil, "secret key")

	c = make([]byte, len(m))
	mac = make([]byte, MACBytes)

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
// Returns the decrypted message and a boolean indicating successful decryption and verification.
func OpenDetached(c, mac, n []byte, pk *PublicKey, sk *SecretKey) (m []byte, err error) {
	support.CheckSize(mac, MACBytes, "nonce")
	support.CheckSize(n, NonceBytes, "nonce")
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
// Returns the decrypted message and a boolean indicating successful encryption.
func SealDetachedAfterPrecomputation(m, n []byte, k *SharedKey) (c, mac []byte) {
	support.CheckSize(n, NonceBytes, "nonce")
	support.NilPanic(k == nil, "shared key")

	c = make([]byte, len(m))
	mac = make([]byte, MACBytes)

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
// Returns the decrypted message and a boolean indicating successful decryption and verification.
func OpenDetachedAfterPrecomputation(c, mac, n []byte, k *SharedKey) (m []byte, err error) {
	support.CheckSize(mac, MACBytes, "nonce")
	support.CheckSize(n, NonceBytes, "nonce")
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
// Returns a ciphertext and a boolean indicating successful encryption.
func SealAnonymous(m []byte, pk *PublicKey) (c []byte) {
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
// Returns the decrypted message and a boolean indicating successful decryption and verification.
func OpenAnonymous(c []byte, pk *PublicKey, sk *SecretKey) (m []byte, err error) {
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
