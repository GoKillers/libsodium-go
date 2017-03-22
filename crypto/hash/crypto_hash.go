package hash

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"

// Bytes represents the size of the hash in bytes
const Bytes int = C.crypto_hash_BYTES

// Primitive returns the name of the used algorithm
func Primitive() string {
	return C.GoString(C.crypto_hash_primitive())
}

// Hash returns the cryptographic hash of input data `in`
func Hash(in []byte) []byte {
	out := make([]byte, Bytes)

	C.crypto_hash(
		(*C.uchar)(&out[0]),
		(*C.uchar)(support.BytePointer(in)),
		C.ulonglong(len(in)))

	return out
}
