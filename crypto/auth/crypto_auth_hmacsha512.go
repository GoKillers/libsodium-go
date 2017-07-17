package auth

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
	"github.com/GoKillers/libsodium-go/crypto/auth/hmacsha512"
	"github.com/GoKillers/libsodium-go/support"
	"hash"
)

// hmacsha512state represents the cryptographic State for HMAC-SHA512.
type hmacsha512state C.crypto_auth_hmacsha512_state

// Write adds data to the hash state.
func (s *hmacsha512state) Write(in []byte) (n int, err error) {
	C.crypto_auth_hmacsha512_update(
		(*C.crypto_auth_hmacsha512_state)(s),
		(*C.uchar)(support.BytePointer(in)),
		C.ulonglong(len(in)))

	return len(in), nil
}

// Sum returns the authentication tag appended to the data in b.
func (s *hmacsha512state) Sum(b []byte) []byte {
	out := make([]byte, hmacsha512.Bytes)

	C.crypto_auth_hmacsha512_final(
		(*C.crypto_auth_hmacsha512_state)(s),
		(*C.uchar)(&out[0]))

	return append(b, out...)
}

// Reset resets the Hash to its initial state.
func (s *hmacsha512state) Reset() {
	panic("HMACSHA512 cannot be reset")
}

// Size returns the size of the authentication tag.
func (s *hmacsha512state) Size() int {
	return hmacsha512.Bytes
}

// BlockSize returns the block size for HMAC-SHA512.
func (s *hmacsha512state) BlockSize() int {
	return 2 * hmacsha512.Bytes
}

// NewHMACSHA512 returns a new HMAC-SHA512 hash using a key.
func NewHMACSHA512(key []byte) hash.Hash {
	s := new(hmacsha512state)

	C.crypto_auth_hmacsha512_init(
		(*C.crypto_auth_hmacsha512_state)(s),
		(*C.uchar)(support.BytePointer(key)),
		C.size_t(len(key)))

	return s
}
