package hash

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
	"github.com/GoKillers/libsodium-go/support"
	"hash"
)

type sha256 C.crypto_hash_sha256_state

// SHA256Bytes represents the size of the hash in bytes
const SHA256Bytes int = C.crypto_hash_sha256_BYTES

// SumSHA256 returns the SHA256 hash of input data `in`
func SumSHA256(in []byte) []byte {
	out := make([]byte, SHA256Bytes)

	C.crypto_hash_sha256(
		(*C.uchar)(&out[0]),
		(*C.uchar)(support.BytePointer(in)),
		C.ulonglong(len(in)))

	return out
}

// NewSHA256 returns a new hash.Hash for computing the SHA256 checksum.
func NewSHA256() hash.Hash {
	state := new(sha256)

	C.crypto_hash_sha256_init(
		(*C.crypto_hash_sha256_state)(state))

	return state
}

// Write adds data to the running hash.
func (s *sha256) Write(p []byte) (int, error) {
	C.crypto_hash_sha256_update(
		(*C.crypto_hash_sha256_state)(s),
		(*C.uchar)(support.BytePointer(p)),
		(C.ulonglong)(len(p)))

	return len(p), nil
}

// Sum returns the calculated hash appended to `b`.
func (s *sha256) Sum(b []byte) []byte {
	out := append(b, make([]byte, SHA256Bytes)...)

	C.crypto_hash_sha256_final(
		(*C.crypto_hash_sha256_state)(s),
		(*C.uchar)(&out[len(b)]))

	return out
}

// Reset resets the hash to its initial state.
func (s *sha256) Reset() {
	C.crypto_hash_sha256_init(
		(*C.crypto_hash_sha256_state)(s))
}

// Size returns the number of bytes Sum will return.
func (s *sha256) Size() int {
	return SHA256Bytes
}

// Block size returns the underlying block size.
// This is not exposed by libsodium, so it returns 1.
func (s *sha256) BlockSize() int {
	return 1
}
