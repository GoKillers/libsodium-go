package auth

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
	"github.com/GoKillers/libsodium-go/crypto/auth/hmacsha256"
	"github.com/GoKillers/libsodium-go/support"
	"hash"
)

// hmacsha256state represents the cryptographic State for HMAC-SHA256.
type hmacsha256state C.crypto_auth_hmacsha256_state

// Write adds data to the hash state.
func (s *hmacsha256state) Write(in []byte) (n int, err error) {
	C.crypto_auth_hmacsha256_update(
		(*C.crypto_auth_hmacsha256_state)(s),
		(*C.uchar)(support.BytePointer(in)),
		C.ulonglong(len(in)))

	return len(in), nil
}

// Sum returns the authentication tag appended to the data in b.
func (s *hmacsha256state) Sum(b []byte) []byte {
	out := make([]byte, hmacsha256.Bytes)

	C.crypto_auth_hmacsha256_final(
		(*C.crypto_auth_hmacsha256_state)(s),
		(*C.uchar)(&out[0]))

	return append(b, out...)
}

// Reset resets the Hash to its initial state.
func (s *hmacsha256state) Reset() {
	panic("HMACSHA256 cannot be reset")
}

// Size returns the size of the authentication tag.
func (s *hmacsha256state) Size() int {
	return hmacsha256.Bytes
}

// BlockSize returns the block size for HMAC-SHA256.
func (s *hmacsha256state) BlockSize() int {
	return 2 * hmacsha256.Bytes
}

// NewHMACSHA256 returns a new HMAC-SHA256 hash using a key.
func NewHMACSHA256(key []byte) hash.Hash {
	s := new(hmacsha256state)

	C.crypto_auth_hmacsha256_init(
		(*C.crypto_auth_hmacsha256_state)(s),
		(*C.uchar)(support.BytePointer(key)),
		C.size_t(len(key)))

	return s
}
