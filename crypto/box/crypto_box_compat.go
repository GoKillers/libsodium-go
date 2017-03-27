package box

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"

// Lengths of various arguments.
const (
	ZeroBytes    = C.crypto_box_ZEROBYTES    // Size of the zero padding of the message.
	BoxZeroBytes = C.crypto_box_BOXZEROBYTES // Size of NaCl box / ciphertext
)

// NaClSealAfterPrecomputation encrypts a message `m` with nonce `n` from a shared key `k`.
// Returns the decrypted message and a boolean indicating successful encryption.
// Note: message `m` requires `ZeroBytes` of padding on the front.
func NaClSealAfterPrecomputation(m, n []byte, k *SharedKey) (c []byte) {
	support.CheckSizeMin(m, ZeroBytes, "message with padding")
	support.CheckSize(n, NonceBytes, "nonce")
	support.NilPanic(k == nil, "shared key")

	c = make([]byte, len(m))

	C.crypto_box_afternm(
		(*C.uchar)(&c[0]),
		(*C.uchar)(support.BytePointer(m)),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))

	return
}

// NaClOpenAfterPrecomputation decrypts a cyphertext `c` using nonce `n` from a shared key `k`.
// Returns the decrypted message and a boolean indicating successful decryption and verification.
// Note: ciphertext `c` requires `BoxZeroBytes` padding on the front.
func NaClOpenAfterPrecomputation(c, n []byte, k *SharedKey) (m []byte, err error) {
	support.CheckSizeMin(c, ZeroBytes, "ciphertext with padding")
	support.CheckSize(n, NonceBytes, "nonce")
	support.NilPanic(k == nil, "shared key")

	m = make([]byte, len(c))

	exit := C.crypto_box_open_afternm(
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

// NaClSeal encrypts a message `m` using nonce `n`, public key `pk` and secret key `sk`.
// Returns a ciphertext and a boolean indicating successful encryption.
// Note: message `m` requires `ZeroBytes` of padding on the front.
func NaClSeal(m, n []byte, pk *PublicKey, sk *SecretKey) (c []byte) {
	support.CheckSizeMin(m, ZeroBytes, "message with padding")
	support.CheckSize(n, NonceBytes, "nonce")
	support.NilPanic(pk == nil, "public key")
	support.NilPanic(sk == nil, "secret key")

	c = make([]byte, len(m))

	C.crypto_box(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		C.ulonglong(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(&sk[0]))

	return
}

// NaClOpen decrypts a ciphertext `c` using nonce `n`, public key `pk` and secret key `sk`.
// Returns the decrypted message and a boolean indicating successful decryption and verification.
// Note: ciphertext `c` requires `BoxZeroBytes` padding on the front.
func NaClOpen(c, n []byte, pk *PublicKey, sk *SecretKey) (m []byte, err error) {
	support.CheckSizeMin(c, ZeroBytes, "ciphertext with padding")
	support.CheckSize(n, NonceBytes, "nonce")
	support.NilPanic(pk == nil, "public key")
	support.NilPanic(sk == nil, "secret key")

	m = make([]byte, len(c))

	exit := C.crypto_box_open(
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
