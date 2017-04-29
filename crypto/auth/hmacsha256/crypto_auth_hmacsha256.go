// Package hmacsha256 contains the libsodium bindings for HMAC-SHA256.
package hmacsha256

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
	Bytes    int = C.crypto_auth_hmacsha256_BYTES
	KeyBytes int = C.crypto_auth_hmacsha256_KEYBYTES
)

// Key represents a secret key.
type Key [KeyBytes]byte

// MAC represents an authentication tag.
type MAC [Bytes]byte

// StateBytes returns the length of the state
func StateBytes() int {
	return int(C.crypto_auth_hmacsha256_statebytes())
}

// New returns the authentication tag for input data and a key.
func New(in []byte, key *Key) *MAC {
	support.NilPanic(key == nil, "key")

	out := new(MAC)

	C.crypto_auth_hmacsha256(
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

	exit := C.crypto_auth_hmacsha256_verify(
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
	C.crypto_auth_hmacsha256_keygen((*C.uchar)(&k[0]))
	return k
}
