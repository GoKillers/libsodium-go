package support

import "strconv"

// KeySizeError is an error that occurs when a key has an incorrect length.
type KeySizeError int

func (k KeySizeError) Error() string {
	return "invalid key size " + strconv.Itoa(int(k))
}

// NonceSizeError is an error that occurs when a nonce has an incorrect length.
type NonceSizeError int

func (k NonceSizeError) Error() string {
	return "invalid nonce size " + strconv.Itoa(int(k))
}

// NilPointerError is an error that occurs when a pointer is a nil pointer
type NilPointerError string

func (k NilPointerError) Error() string {
	return string(k) + " is a nil pointer"
}

// VerificationError is an error that occurs when the verification of
// a signature or authentication tag fails.
type VerificationError struct {}

func (k VerificationError) Error() string {
	return "verification failed"
}
