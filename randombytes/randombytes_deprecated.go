package randombytes

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

// Deprecated: use SeedBytes instead
func RandomBytesSeedBytes() int {
	return SeedBytes
}

// Deprecated: use Bytes() instead
func RandomBytes(size int) []byte {
	return Bytes(size)
}

// Deprecated: use Read() instead
func RandomBytesBuf(buf []byte) {
	Read(buf)
}

// Deprecated: use ReadDeterministic() instead
func RandomBytesBufDeterministic(buf, seed []byte) {
	ReadDeterministic(buf, seed)
}

// Deprecated: use Random() instead
func RandomBytesRandom() uint32 {
	return Random()
}

// Deprecated: use Uniform() instead
func RandomBytesUniform(upperBound uint32) uint32 {
	return Uniform(upperBound)
}

// Deprecated: use Stir() instead
func RandomBytesStir() {
	Stir()
}

// Deprecated: use Close() instead
func RandomBytesClose() {
	Close()
}

// Deprecated: use SetImplementation() instead
func RandomBytesSetImplementation(impl *C.struct_randombytes_implementation) int {
	return SetImplementation(Implementation(impl))
}

// Deprecated: use Salsa20Implementation() instead
var RandomBytesSalsa20Implementation *C.struct_randombytes_implementation = &C.randombytes_salsa20_implementation

// Deprecated: use SysRandomImplementation() instead
var RandomBytesSysRandomImplementation *C.struct_randombytes_implementation = &C.randombytes_sysrandom_implementation
