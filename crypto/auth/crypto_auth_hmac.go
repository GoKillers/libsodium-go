package auth

import (
	"io"
)

// HMAC is a modified version of hash.Hash
type HMAC interface {
	// Write (from the io.Writer interface) adds data to the hash state.
	io.Writer

	// Sum appends the data in b with the result of the hash.
	// Contrary to Sum in hash.Hash this does affect the state.
	// Consider this the final action.
	Sum(b []byte) []byte

	// Size returns the size of the hash in bytes.
	Size() int

	// BlockSize returns the block size for the underlying hash function.
	BlockSize() int
}
