package auth

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"

// Bytes returns the length of an authentication tag
func Bytes() int {
	return int(C.crypto_auth_bytes())
}

// KeyBytes returns the length of a key
func KeyBytes() int {
	return int(C.crypto_auth_keybytes())
}

// Primitive returns the name of the used algorithm
func Primitive() string {
	return C.GoString(C.crypto_auth_primitive())
}

// Auth returns the authentication tag for input data `in` and a key `k`
func Auth(in, key []byte) []byte {
	support.CheckSize(key, KeyBytes(), "key")

	out := make([]byte, Bytes())

	C.crypto_auth(
		(*C.uchar)(&out[0]),
		(*C.uchar)(support.BytePointer(in)),
		(C.ulonglong)(len(in)),
		(*C.uchar)(&key[0]))

	return out
}

// Verify if the authentication tag `h` is valid for input data `in` and key `k`.
func Verify(h, in, key []byte) bool {
	support.CheckSize(h, Bytes(), "hmac")
	support.CheckSize(key, KeyBytes(), "key")

	exit := int(C.crypto_auth_verify(
		(*C.uchar)(&h[0]),
		(*C.uchar)(support.BytePointer(in)),
		(C.ulonglong)(len(in)),
		(*C.uchar)(&key[0])))

	return exit == 0
}

// KeyGen generates a secret key
func KeyGen() []byte {
	k := make([]byte, KeyBytes())
	C.crypto_auth_keygen((*C.uchar)(&k[0]))
	return k
}
