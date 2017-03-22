// Package aead contains bindings for authenticated encryption with additional data.
package aead

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "crypto/cipher"

// Sodium should always be initialised
func init() {
	C.sodium_init()
}

// AEAD is and extended version of cipher.AEAD
type AEAD interface {
	cipher.AEAD

	// SealDetached encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice and the authentication code (mac) separately.
	// The nonce must be NonceSize() bytes long and unique for all time, for a given key.
	// The mac is Overhead() bytes long.
	//
	// The plaintext and dst may alias exactly or not at all. To reuse
	// plaintext's storage for the encrypted output, use plaintext[:0] as dst.
	SealDetached(dst, nonce, plaintext, additionalData []byte) ([]byte, []byte)

	// OpenDetached decrypts a ciphertext, authenticates the additional data using
	// the autentication code (mac) and, if successful, appends the resulting plaintext
	// to dst, returning the updated slice. The nonce must be NonceSize()
	// bytes long and both it and the additional data must match the
	// value passed to Seal.
	//
	// The ciphertext and dst may alias exactly or not at all. To reuse
	// ciphertext's storage for the decrypted output, use ciphertext[:0] as dst.
	//
	// Even if the function fails, the contents of dst, up to its capacity,
	// may be overwritten.
	OpenDetached(dst, nonce, ciphertext, mac, additionalData []byte) ([]byte, error)
}

// appendSlices appends a slice with a number of empty bytes and
// returns the new slice and a slice pointing to the empty data.
func appendSlices(in []byte, n int) ([]byte, []byte) {
	slice := append(in, make([]byte, n)...)
	return slice, slice[len(in):]
}
