package hash

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"

const (
	// Bytes is the size of the hash in bytes
	Bytes int = C.crypto_hash_BYTES

	// Primitive is the name of the used algorithm
	Primitive string = C.crypto_hash_PRIMITIVE
)

// Sum returns the cryptographic hash of input data `in`
func Sum(in []byte) []byte {
	out := make([]byte, Bytes)

	C.crypto_hash(
		(*C.uchar)(&out[0]),
		(*C.uchar)(support.BytePointer(in)),
		C.ulonglong(len(in)))

	return out
}
