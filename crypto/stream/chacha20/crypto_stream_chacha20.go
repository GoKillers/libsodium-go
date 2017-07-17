// Package chacha20 contains the libsodium bindings for the ChaCha20 stream cipher.
package chacha20

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
	KeyBytes   int = C.crypto_stream_chacha20_KEYBYTES
	NonceBytes int = C.crypto_stream_chacha20_NONCEBYTES
)

// KeyStream fills an output buffer `c` with pseudo random bytes using a nonce `n` and a secret key `k`.
func KeyStream(c []byte, n *[NonceBytes]byte, k *[KeyBytes]byte) {
	support.NilPanic(n == nil, "nonce")
	support.NilPanic(k == nil, "key")

	if len(c) == 0 {
		return
	}

	C.crypto_stream_chacha20(
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))
}

// XORKeyStream encrypts a message `m` using a nonce `n` and a secret key `k` and puts the resulting ciphertext into `c`.
// If `m` and `c` are the same slice, in-place encryption is performed.
func XORKeyStream(c, m []byte, n *[NonceBytes]byte, k *[KeyBytes]byte) {
	support.NilPanic(n == nil, "nonce")
	support.NilPanic(k == nil, "key")
	support.CheckSizeGreaterOrEqual(c, m, "output", "input")

	if len(c) == 0 {
		return
	}

	C.crypto_stream_chacha20_xor(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0]))
}

// XORKeyStreamIC encrypts a message `m` using a nonce `n` and a secret key `k`,
// but with a block counter starting at `ic`.
// If `m` and `c` are the same slice, in-place encryption is performed.
func XORKeyStreamIC(c, m []byte, n *[NonceBytes]byte, k *[KeyBytes]byte, ic uint64) {
	support.NilPanic(n == nil, "nonce")
	support.NilPanic(k == nil, "key")
	support.CheckSizeGreaterOrEqual(c, m, "output", "input")

	if len(c) == 0 {
		return
	}

	C.crypto_stream_chacha20_xor_ic(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(C.uint64_t)(ic),
		(*C.uchar)(&k[0]))
}

// GenerateKey generates a secret key
func GenerateKey() *[KeyBytes]byte {
	k := new([KeyBytes]byte)

	C.crypto_stream_chacha20_keygen((*C.uchar)(&k[0]))

	return k
}
