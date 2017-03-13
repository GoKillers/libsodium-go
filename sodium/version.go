package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

func SodiumVersionString() string {
	return C.GoString(C.sodium_version_string())
}

func SodiumLibaryVersionMajor() int {
	return int(C.sodium_library_version_major())
}

func SodiumLibaryVersionMinor() int {
	return int(C.sodium_library_version_minor())
}

func SodiumLibaryMinimal() bool {
	return int(C.sodium_library_minimal()) != 0
}
