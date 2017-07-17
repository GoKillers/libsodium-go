// Package generichash contains the libsodium bindings for generic hashing.
package generichash

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
	"github.com/GoKillers/libsodium-go/support"
	"hash"
)

// The following constants reflect the properties of the generic hash:
const (
	BytesMin    int    = C.crypto_generichash_BYTES_MIN    // Minimum hash size in bytes
	BytesMax    int    = C.crypto_generichash_BYTES_MAX    // Maximum hash size in bytes
	Bytes       int    = C.crypto_generichash_BYTES        // Default hash size in bytes
	KeyBytesMin int    = C.crypto_generichash_KEYBYTES_MIN // Minimum key size in bytes
	KeyBytesMax int    = C.crypto_generichash_KEYBYTES_MAX // Maximum key size in bytes
	KeyBytes    int    = C.crypto_generichash_KEYBYTES     // Default key size in bytes
	Primitive   string = C.crypto_generichash_PRIMITIVE    // Name of the algorithm used for generic hashing
)

type state struct {
	l C.size_t
	s *C.crypto_generichash_state
}

// Sum returns the cryptographic hash of input data `in` in output buffer `out`.
// A key `key` can be given to create a hash unique to that key.
// The length of the hash is determined by the length of the output buffer,
// which has to be between BytesMin and BytesMax (inclusive).
// The size of `key` can either be 0 or between KeyBytesMin and KeyBytesMax (inclusive).
func Sum(out, in, key []byte) {
	support.CheckSizeInRange(out, BytesMin, BytesMax, "out")

	if len(key) > 0 {
		support.CheckSizeInRange(key, KeyBytesMin, KeyBytesMax, "key")
	}

	C.crypto_generichash(
		(*C.uchar)(support.BytePointer(out)), C.size_t(len(out)),
		(*C.uchar)(support.BytePointer(in)), C.ulonglong(len(in)),
		(*C.uchar)(support.BytePointer(key)), C.size_t(len(key)))
}

// New returns a new hash.Sum for computing the generic hash.
// A key `key` can be given to create a hash unique to that key.
// `size` determines the length of the hash and has to be between BytesMin and BytesMax.
// The size `key` can either be 0 or between KeyBytesMin and KeyBytesMax (inclusive).
func New(size int, key []byte) hash.Hash {
	support.CheckIntInRange(size, BytesMin, BytesMax, "hash size")

	if len(key) > 0 {
		support.CheckSizeInRange(key, KeyBytesMin, KeyBytesMax, "key")
	}

	s := &state{
		l: C.size_t(size),
		s: new(C.crypto_generichash_state),
	}

	C.crypto_generichash_init(s.s,
		(*C.uchar)(support.BytePointer(key)),
		C.size_t(len(key)),
		s.l)

	return s
}

// Write adds data to the running hash.
func (s *state) Write(p []byte) (int, error) {
	C.crypto_generichash_update(s.s,
		(*C.uchar)(support.BytePointer(p)),
		C.ulonglong(len(p)))

	return len(p), nil
}

// Sum returns the calculated hash appended to `b`.
func (s *state) Sum(b []byte) []byte {
	out := append(b, make([]byte, s.l)...)

	C.crypto_generichash_final(s.s,
		(*C.uchar)(&out[len(b)]),
		s.l)

	return out
}

// Reset resets the hash to its initial state.
func (s *state) Reset() {
	panic("This hash can not be reset")
}

// Size returns the number of bytes Sum will return.
func (s *state) Size() int {
	return int(s.l)
}

// Block size returns the underlying block size.
// This is not exposed by libsodium, so it returns 1.
func (s *state) BlockSize() int {
	return 1
}

// GenerateKey generates a key for use with the generic hash
func GenerateKey() []byte {
	k := make([]byte, KeyBytes)
	C.crypto_generichash_keygen((*C.uchar)(&k[0]))
	return k
}
