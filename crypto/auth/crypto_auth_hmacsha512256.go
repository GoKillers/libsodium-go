package auth

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
	"github.com/GoKillers/libsodium-go/crypto/auth/hmacsha512256"
	"github.com/GoKillers/libsodium-go/support"
	"hash"
)

// hmacsha512256state represents the cryptographic State for HMAC-SHA512256.
type hmacsha512256state C.crypto_auth_hmacsha512256_state

// Write adds data to the hash state.
func (s *hmacsha512256state) Write(in []byte) (n int, err error) {
	C.crypto_auth_hmacsha512256_update(
		(*C.crypto_auth_hmacsha512256_state)(s),
		(*C.uchar)(support.BytePointer(in)),
		C.ulonglong(len(in)))

	return len(in), nil
}

// Sum returns the authentication tag appended to the data in b.
func (s *hmacsha512256state) Sum(b []byte) []byte {
	out := make([]byte, hmacsha512256.Bytes)

	C.crypto_auth_hmacsha512256_final(
		(*C.crypto_auth_hmacsha512256_state)(s),
		(*C.uchar)(&out[0]))

	return append(b, out...)
}

// Reset resets the Hash to its initial state.
func (s *hmacsha512256state) Reset() {
	panic("HMACSHA512256 cannot be reset")
}

// Size returns the size of the authentication tag.
func (s *hmacsha512256state) Size() int {
	return hmacsha512256.Bytes
}

// BlockSize returns the block size for HMAC-SHA512256.
func (s *hmacsha512256state) BlockSize() int {
	return 2 * hmacsha512256.Bytes
}

// NewHMACSHA512256 returns a new HMAC-SHA512256 hash using a key.
func NewHMACSHA512256(key []byte) hash.Hash {
	s := new(hmacsha512256state)

	C.crypto_auth_hmacsha512256_init(
		(*C.crypto_auth_hmacsha512256_state)(s),
		(*C.uchar)(support.BytePointer(key)),
		C.size_t(len(key)))

	return s
}
