// Package salsa2012 contains the libsodium bindings for the Salsa20 stream cipher reduced to 12 rounds.
package salsa2012

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"

// Sodium should always be initialised
func init() {
	C.sodium_init()
}

// Required length of secret key and nonce
const (
	KeyBytes   int = C.crypto_stream_salsa2012_KEYBYTES
	NonceBytes int = C.crypto_stream_salsa2012_NONCEBYTES
)

// Nonce represents a cryptographic nonce
type Nonce [NonceBytes]byte

// Key represents a secret key
type Key [KeyBytes]byte

// KeyStream fills an output buffer `c` with pseudo random bytes using a nonce `n` and a secret key `k`.
func KeyStream(c []byte, n *Nonce, k *Key) {
	support.NilPanic(n == nil, "nonce")
	support.NilPanic(k == nil, "key")

	if len(c) == 0 {
		return
	}

	C.crypto_stream_salsa2012(
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))
}

// XORKeyStream encrypts a message `m` using a nonce `n` and a secret key `k` and puts the resulting ciphertext into `c`.
// If `m` and `c` are the same slice, in-place encryption is performed.
func XORKeyStream(c, m []byte, n *Nonce, k *Key) {
	support.NilPanic(n == nil, "nonce")
	support.NilPanic(k == nil, "key")
	support.CheckSizeSmaller(c, m, "output", "input")

	if len(c) == 0 {
		return
	}

	C.crypto_stream_salsa2012_xor(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))
}

// GenerateKey generates a secret key
func GenerateKey() *Key {
	k := new(Key)

	C.crypto_stream_salsa2012_keygen((*C.uchar)(&k[0]))

	return k
}
