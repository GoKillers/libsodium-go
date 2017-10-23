// Package stream contains the libsodium bindings for the XSalsa20 stream cipher.
package stream

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"

// Sodium should always be initialised
func init() {
	C.sodium_init()
}

// Stream byte lengths and algorithm name
const (
	KeyBytes        = C.crypto_stream_KEYBYTES         // Length of a secret key
	NonceBytes      = C.crypto_stream_NONCEBYTES       // Length of a nonce
	MessageBytesMax = C.crypto_stream_MESSAGEBYTES_MAX // Maximum length of a message
	Primitive       = C.crypto_stream_PRIMITIVE        // Name of the used algorithm
)

// KeyStream fills an output buffer `c` with pseudo random bytes using a nonce `n` and a secret key `k`.
func KeyStream(c []byte, n *[NonceBytes]byte, k *[KeyBytes]byte) {
	support.NilPanic(n == nil, "nonce")
	support.NilPanic(k == nil, "key")

	if len(c) == 0 {
		return
	}

	C.crypto_stream(
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))
}

// XORKeyStream encrypts a message `m` using a nonce `n` and a secret key `k` and puts the resulting ciphertext into `c`.
// If `m` and `c` are the same slice, in-place encryption is performed.
func XORKeyStream(c, m []byte, n *[NonceBytes]byte, k *[KeyBytes]byte) {
	support.CheckSizeMax(m, MessageBytesMax, "message")
	support.NilPanic(n == nil, "nonce")
	support.NilPanic(k == nil, "key")
	support.CheckSizeGreaterOrEqual(c, m, "output", "input")

	if len(c) == 0 {
		return
	}

	C.crypto_stream_xor(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))
}

// GenerateKey generates a secret key
func GenerateKey() *[KeyBytes]byte {
	c := new([KeyBytes]byte)

	C.crypto_stream_keygen((*C.uchar)(&c[0]))

	return c
}
