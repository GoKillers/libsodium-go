package auth

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
	"github.com/GoKillers/libsodium-go/crypto/auth/hmacsha512256"
	"github.com/GoKillers/libsodium-go/support"
)

// HMACSHA512256 represents the cryptographic State for HMAC-SHA256.
type HMACSHA512256 C.crypto_auth_hmacsha512256_state

// Write adds data to the hash state.
func (s *HMACSHA512256) Write(in []byte) (n int, err error) {
	C.crypto_auth_hmacsha512256_update(
		(*C.crypto_auth_hmacsha512256_state)(s),
		(*C.uchar)(support.BytePointer(in)),
		C.ulonglong(len(in)))

	return len(in), nil
}

// Sum returns the authentication tag appended to the data in b.
func (s *HMACSHA512256) Sum(b []byte) []byte {
	out := make([]byte, hmacsha512256.Bytes)

	C.crypto_auth_hmacsha512256_final(
		(*C.crypto_auth_hmacsha512256_state)(s),
		(*C.uchar)(&out[0]))

	return append(b, out...)
}

// Size returns the size of the authentication tag.
func (s *HMACSHA512256) Size() int {
	return hmacsha512256.Bytes
}

// BlockSize returns the block size for HMAC-SHA256.
func (s *HMACSHA512256) BlockSize() int {
	return 4 * hmacsha512256.Bytes
}

// NewHMACSHA512256 returns a new HMAC-SHA256 hash using a key.
func NewHMACSHA512256(key []byte) HMAC {
	s := new(HMACSHA512256)

	C.crypto_auth_hmacsha512256_init(
		(*C.crypto_auth_hmacsha512256_state)(s),
		(*C.uchar)(support.BytePointer(key)),
		C.size_t(len(key)))

	return s
}
