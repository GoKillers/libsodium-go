// Package support implements support functions and errors that are used by by other libsodium-go packages.
package support

import (
	"fmt"
	"unsafe"
)

// CheckSize checks if the length of a byte slice is equal to the expected length,
// and panics when this is not the case.
func CheckSize(buf []byte, expected int, descrip string) {
	if len(buf) != expected {
		panic(fmt.Sprintf("Incorrect %s buffer size, expected (%d), got (%d).", descrip, expected, len(buf)))
	}
}

// CheckSizeMin checks if the length of a byte slice is greater or equal than a minimum length,
// and panics when this is not the case.
func CheckSizeMin(buf []byte, min int, descrip string) {
	if len(buf) < min {
		panic(fmt.Sprintf("Incorrect %s buffer size, expected (>%d), got (%d).", descrip, min, len(buf)))
	}
}

// CheckIntInRange checks if the size of an integer is between a lower and upper boundaries.
func CheckIntInRange(n int, min int, max int, descrip string) {
	if n < min || n > max {
		panic(fmt.Sprintf("Incorrect %s size, expected (%d - %d), got (%d).", descrip, min, max, n))
	}
}

// CheckSizeInRange checks if the length of a byte slice is between a lower and upper boundaries.
func CheckSizeInRange(buf []byte, min int, max int, descrip string) {
	if len(buf) < min || len(buf) > max {
		panic(fmt.Sprintf("Incorrect %s buffer size, expected (%d - %d), got (%d).", descrip, min, max, len(buf)))
	}
}

// CheckSizeGreaterOrEqual checks if the length of a byte slice is greater or equal to that of a second byte slice.
func CheckSizeGreaterOrEqual(a, b []byte, aDescription, bDescription string) {
	if len(a) < len(b) {
		panic(fmt.Sprintf("%s smaller than %s", aDescription, bDescription))
	}
}

// NilPanic is a shorthand that results in a panic when called with true.
func NilPanic(t bool, description string) {
	if t {
		panic(description + " is a nil pointer")
	}
}

// BytePointer returns a pointer to the start of a byte slice, or nil when the slice is empty.
func BytePointer(b []byte) *uint8 {
	if len(b) > 0 {
		return &b[0]
	} else {
		return nil
	}
}

// AlignedSlice returns a memory aligned slice
func AlignedSlice(size, alignment int) []byte {
	slice := make([]byte, size+alignment)
	offset := alignment - int(uintptr(unsafe.Pointer(&slice[0])))%alignment
	return slice[offset : offset+size]
}
