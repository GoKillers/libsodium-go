package auth

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
	"github.com/GoKillers/libsodium-go/crypto/auth/hmacsha256"
	"github.com/GoKillers/libsodium-go/support"
)

// HMACSHA256 represents the cryptographic State for HMAC-SHA256.
type HMACSHA256 C.crypto_auth_hmacsha256_state

// Write adds data to the hash state.
func (s *HMACSHA256) Write(in []byte) (n int, err error) {
	C.crypto_auth_hmacsha256_update(
		(*C.crypto_auth_hmacsha256_state)(s),
		(*C.uchar)(support.BytePointer(in)),
		C.ulonglong(len(in)))

	return len(in), nil
}

// Sum returns the authentication tag appended to the data in b.
func (s *HMACSHA256) Sum(b []byte) []byte {
	out := make([]byte, hmacsha256.Bytes)

	C.crypto_auth_hmacsha256_final(
		(*C.crypto_auth_hmacsha256_state)(s),
		(*C.uchar)(&out[0]))

	return append(b, out...)
}

// Size returns the size of the authentication tag.
func (s *HMACSHA256) Size() int {
	return hmacsha256.Bytes
}

// BlockSize returns the block size for HMAC-SHA256.
func (s *HMACSHA256) BlockSize() int {
	return 2 * hmacsha256.Bytes
}

// NewHMACSHA256 returns a new HMAC-SHA256 hash using a key.
func NewHMACSHA256(key []byte) HMAC {
	s := new(HMACSHA256)

	C.crypto_auth_hmacsha256_init(
		(*C.crypto_auth_hmacsha256_state)(s),
		(*C.uchar)(support.BytePointer(key)),
		C.size_t(len(key)))

	return s
}
