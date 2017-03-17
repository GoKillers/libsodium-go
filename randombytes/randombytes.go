package randombytes

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"
import "unsafe"

func RandomBytesSeedBytes() int {
	return int(C.randombytes_seedbytes())
}

func RandomBytes(size int) []byte {
	buf := make([]byte, size)
	RandomBytesBuf(buf)
	return buf
}

func RandomBytesBuf(buf []byte) {
	if len(buf) > 0 {
		C.randombytes_buf(unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	}
}

func RandomBytesBufDeterministic(buf []byte, seed []byte) {
	support.CheckSize(seed, RandomBytesSeedBytes(), "seed")
	if len(buf) > 0 {
		C.randombytes_buf_deterministic(
			unsafe.Pointer(&buf[0]),
			C.size_t(len(buf)),
			(*C.uchar)(&seed[0]))
	}
}

func RandomBytesRandom() uint32 {
	return uint32(C.randombytes_random())
}

func RandomBytesUniform(upperBound uint32) uint32 {
	return uint32(C.randombytes_uniform(C.uint32_t(upperBound)))
}

func RandomBytesStir() {
	C.randombytes_stir()
}

func RandomBytesClose() {
	C.randombytes_close()
}

func RandomBytesSetImplementation(impl *C.struct_randombytes_implementation) int {
	return int(C.randombytes_set_implementation(impl))
}

func RandomBytesImplementationName() string {
	return C.GoString(C.randombytes_implementation_name())
}

// From randombytes_salsa20_random.h
var RandomBytesSalsa20Implementation *C.struct_randombytes_implementation = &C.randombytes_salsa20_implementation

// From randombytes_sysrandom.h
var RandomBytesSysRandomImplementation *C.struct_randombytes_implementation = &C.randombytes_sysrandom_implementation
