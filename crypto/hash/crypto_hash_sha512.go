package hash

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
	"github.com/GoKillers/libsodium-go/support"
	"hash"
)

type sha512 C.crypto_hash_sha512_state

// SHA512Bytes represents the size of the hash in bytes
const SHA512Bytes int = C.crypto_hash_sha512_BYTES

// SumSHA512 returns the SHA512 hash of input data `in`
func SumSHA512(in []byte) []byte {
	out := make([]byte, SHA512Bytes)

	C.crypto_hash_sha512(
		(*C.uchar)(&out[0]),
		(*C.uchar)(support.BytePointer(in)),
		C.ulonglong(len(in)))

	return out
}

// NewSHA512 returns a new hash.Hash for computing the SHA512 checksum.
func NewSHA512() hash.Hash {
	state := new(sha512)

	C.crypto_hash_sha512_init(
		(*C.crypto_hash_sha512_state)(state))

	return state
}

// Write adds data to the running hash.
func (s *sha512) Write(p []byte) (int, error) {
	C.crypto_hash_sha512_update(
		(*C.crypto_hash_sha512_state)(s),
		(*C.uchar)(support.BytePointer(p)),
		(C.ulonglong)(len(p)))

	return len(p), nil
}

// Sum returns the calculated hash appended to `b`.
func (s *sha512) Sum(b []byte) []byte {
	out := append(b, make([]byte, SHA512Bytes)...)

	C.crypto_hash_sha512_final(
		(*C.crypto_hash_sha512_state)(s),
		(*C.uchar)(&out[len(b)]))

	return out
}

// Reset resets the hash to its initial state.
func (s *sha512) Reset() {
	C.crypto_hash_sha512_init(
		(*C.crypto_hash_sha512_state)(s))
}

// Size returns the number of bytes Sum will return.
func (s *sha512) Size() int {
	return SHA512Bytes
}

// Block size returns the underlying block size.
// This is not exposed by libsodium, so it returns 1.
func (s *sha512) BlockSize() int {
	return 1
}
