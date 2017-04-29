// Package auth contains the libsodium bindings for secret-key authentication.
package auth

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"

func init() {
	C.sodium_init()
}

// Sizes of authentication tag and key, and the name of the used primitive.
const (
	Bytes     int    = C.crypto_auth_BYTES
	KeyBytes  int    = C.crypto_auth_KEYBYTES
	Primitive string = C.crypto_auth_PRIMITIVE
)

// Key represents a secret key.
type Key [KeyBytes]byte

// MAC represents an authentication tag.
type MAC [Bytes]byte

// New returns the authentication tag for input data and a key.
func New(in []byte, key *Key) *MAC {
	support.NilPanic(key == nil, "key")

	out := new(MAC)

	C.crypto_auth(
		(*C.uchar)(&out[0]),
		(*C.uchar)(support.BytePointer(in)),
		(C.ulonglong)(len(in)),
		(*C.uchar)(&key[0]))

	return out
}

// CheckMAC if the authentication tag is valid for input data and a key.
func CheckMAC(in []byte, h *MAC, key *Key) (err error) {
	support.NilPanic(h == nil, "hmac")
	support.NilPanic(key == nil, "key")

	exit := C.crypto_auth_verify(
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
func GenerateKey() *Key {
	k := new(Key)
	C.crypto_auth_keygen((*C.uchar)(&k[0]))
	return k
}
