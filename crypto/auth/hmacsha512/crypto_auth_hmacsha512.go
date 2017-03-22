package hmacsha512

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
	"github.com/GoKillers/libsodium-go/support"
	"unsafe"
)

// Bytes returns the length of an authentication tag
func Bytes() int {
	return int(C.crypto_auth_hmacsha512_bytes())
}

// KeyBytes returns the length of a key
func KeyBytes() int {
	return int(C.crypto_auth_hmacsha512_keybytes())
}

// StateBytes returns the length of the state
func StateBytes() int {
	return int(C.crypto_auth_hmacsha512_statebytes())
}

// Auth returns the authentication tag for input data `in` and a key `k`
func Auth(in, key []byte) []byte {
	support.CheckSize(key, KeyBytes(), "key")

	out := make([]byte, Bytes())

	C.crypto_auth_hmacsha512(
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

	exit := int(C.crypto_auth_hmacsha512_verify(
		(*C.uchar)(&h[0]),
		(*C.uchar)(support.BytePointer(in)),
		(C.ulonglong)(len(in)),
		(*C.uchar)(&key[0])))

	return exit == 0
}

// Init initialises a state using a key.
func Init(key []byte) []byte {
	state := make([]byte, StateBytes())

	C.crypto_auth_hmacsha512_init(
		(*C.crypto_auth_hmacsha512_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(support.BytePointer(key)),
		(C.size_t)(len(key)))

	return state
}

// Update the state with input data `in`.
func Update(state, in []byte) {
	C.crypto_auth_hmacsha512_update(
		(*C.crypto_auth_hmacsha512_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(support.BytePointer(in)),
		(C.ulonglong)(len(in)))
}

// Final returns the authentication tag for a state.
func Final(state []byte) []byte {
	out := make([]byte, Bytes())

	C.crypto_auth_hmacsha512_final(
		(*C.crypto_auth_hmacsha512_state)(unsafe.Pointer(&state[0])),
		(*C.uchar)(&out[0]))

	return out
}

// KeyGen generates a secret key
func KeyGen() []byte {
	k := make([]byte, KeyBytes())
	C.crypto_auth_hmacsha512_keygen((*C.uchar)(&k[0]))
	return k
}

