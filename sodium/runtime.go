package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

func RuntimeGetCpuFeatures() int {
	return int(C.sodium_runtime_get_cpu_features())
}

func RuntimeHasNeon() bool {
	return C.sodium_runtime_has_neon() != 0
}

func RuntimeHasSse2() bool {
	return C.sodium_runtime_has_sse2() != 0
}

func RuntimeHasSse3() bool {
	return C.sodium_runtime_has_sse3() != 0
}
