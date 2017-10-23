// Package hmacsha512256 contains the libsodium bindings for HMAC-SHA512256.
package hmacsha512256

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"

func init() {
	C.sodium_init()
}

// Sizes of authentication tag and key.
const (
	Bytes    int = C.crypto_auth_hmacsha512256_BYTES
	KeyBytes int = C.crypto_auth_hmacsha512256_KEYBYTES
)

// New returns the authentication tag for input data and a key.
func New(in []byte, key *[KeyBytes]byte) *[Bytes]byte {
	support.NilPanic(key == nil, "key")

	out := new([Bytes]byte)

	C.crypto_auth_hmacsha512256(
		(*C.uchar)(&out[0]),
		(*C.uchar)(support.BytePointer(in)),
		(C.ulonglong)(len(in)),
		(*C.uchar)(&key[0]))

	return out
}

// CheckMAC if the authentication tag is valid for input data and a key.
func CheckMAC(in []byte, h *[Bytes]byte, key *[KeyBytes]byte) (err error) {
	support.NilPanic(h == nil, "hmac")
	support.NilPanic(key == nil, "key")

	exit := C.crypto_auth_hmacsha512256_verify(
		(*C.uchar)(&h[0]),
		(*C.uchar)(support.BytePointer(in)),
		(C.ulonglong)(len(in)),
		(*C.uchar)(&key[0]))

	if exit != 0 {
		err = support.VerificationError{}
	}

	return
}

// GenerateKey generates a secret key.
func GenerateKey() *[KeyBytes]byte {
	k := new([KeyBytes]byte)
	C.crypto_auth_hmacsha512256_keygen((*C.uchar)(&k[0]))
	return k
}
