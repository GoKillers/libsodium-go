package sodium

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

// VersionString returns the libsodium version string
func VersionString() string {
	return C.GoString(C.sodium_version_string())
}

// LibraryVersionMajor returns the library major version number
func LibraryVersionMajor() int {
	return int(C.sodium_library_version_major())
}

// LibraryVersionMinor returns the library minor version number
func LibraryVersionMinor() int {
	return int(C.sodium_library_version_minor())
}

// LibraryMinimal returns true for a minimal build
func LibraryMinimal() bool {
	return int(C.sodium_library_minimal()) != 0
}
