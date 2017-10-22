package aead

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
	"github.com/GoKillers/libsodium-go/crypto/aead/aes256gcm"
	"github.com/GoKillers/libsodium-go/support"
	"unsafe"
)

// AES256GCM state struct
type AES256GCM struct {
	// Represents crypto_aead_aes256gcm_state, which must be 16 byte aligned.
	// This is not enforced by Go, so 16 extra bytes are allocated and
	// the 512 aligned bytes in them are used.
	state1 [512 + 16]byte
}

// NewAES256GCM returns a AES256GCM cipher for an AES256 key.
func NewAES256GCM(k *[aes256gcm.KeyBytes]byte) AEAD {
	support.NilPanic(k == nil, "key")

	ctx := new(AES256GCM)

	C.crypto_aead_aes256gcm_beforenm(
		ctx.state(),
		(*C.uchar)(&k[0]))

	return ctx
}

// state returns a pointer to the space allocated for the state
func (a *AES256GCM) state() *C.crypto_aead_aes256gcm_state {
	var offset uintptr
	mod := uintptr(unsafe.Pointer(&a.state1)) % 16

	if mod == 0 {
		offset = mod
	} else {
		offset = 16 - mod
	}

	return (*C.crypto_aead_aes256gcm_state)(unsafe.Pointer(&a.state1[offset]))
}

// NonceSize returns the size of the nonce for Seal() and Open()
func (a *AES256GCM) NonceSize() int {
	return aes256gcm.NonceBytes
}

// Overhead returns the size of the MAC overhead for Seal() and Open()
func (a *AES256GCM) Overhead() int {
	return aes256gcm.ABytes
}

// Seal encrypts plaintext using nonce and additional data and appends it to a destination.
// See aead.AEAD for details.
func (a *AES256GCM) Seal(dst, nonce, plaintext, additionalData []byte) (ret []byte) {
	support.CheckSize(nonce, a.NonceSize(), "nonce")

	ret, c := appendSlices(dst, len(plaintext)+a.Overhead())

	C.crypto_aead_aes256gcm_encrypt_afternm(
		(*C.uchar)(&c[0]),
		(*C.ulonglong)(nil),
		(*C.uchar)(support.BytePointer(plaintext)),
		(C.ulonglong)(len(plaintext)),
		(*C.uchar)(support.BytePointer(additionalData)),
		(C.ulonglong)(len(additionalData)),
		(*C.uchar)(nil),
		(*C.uchar)(&nonce[0]),
		a.state())

	return
}

// Open decrypts a ciphertext using a nonce and additional data and appends the result to a destination.
// See aead.AEAD for details.
func (a *AES256GCM) Open(dst, nonce, ciphertext, additionalData []byte) (ret []byte, err error) {
	support.CheckSize(nonce, a.NonceSize(), "nonce")
	support.CheckSizeMin(ciphertext, a.Overhead(), "ciphertext")

	ret, m := appendSlices(dst, len(ciphertext)-a.Overhead())

	exit := C.crypto_aead_aes256gcm_decrypt_afternm(
		(*C.uchar)(support.BytePointer(m)),
		(*C.ulonglong)(nil),
		(*C.uchar)(nil),
		(*C.uchar)(&ciphertext[0]),
		(C.ulonglong)(len(ciphertext)),
		(*C.uchar)(support.BytePointer(additionalData)),
		(C.ulonglong)(len(additionalData)),
		(*C.uchar)(&nonce[0]),
		a.state())

	if exit != 0 {
		err = &support.VerificationError{}
	}

	return
}

// SealDetached encrypts plaintext using nonce and additional data and appends it to a destination.
// See aead.AEAD for details.
func (a *AES256GCM) SealDetached(dst, nonce, plaintext, additionalData []byte) (ret, mac []byte) {
	support.CheckSize(nonce, a.NonceSize(), "nonce")

	ret, c := appendSlices(dst, len(plaintext))
	mac = make([]byte, a.Overhead())

	C.crypto_aead_aes256gcm_encrypt_detached_afternm(
		(*C.uchar)(support.BytePointer(c)),
		(*C.uchar)(&mac[0]),
		(*C.ulonglong)(nil),
		(*C.uchar)(support.BytePointer(plaintext)),
		(C.ulonglong)(len(plaintext)),
		(*C.uchar)(support.BytePointer(additionalData)),
		(C.ulonglong)(len(additionalData)),
		(*C.uchar)(nil),
		(*C.uchar)(&nonce[0]),
		a.state())

	return
}

// OpenDetached decrypts a ciphertext using a nonce, mac and additional data and appends the result to a destination.
// See aead.AEAD for details.
func (a *AES256GCM) OpenDetached(dst, nonce, ciphertext, mac, additionalData []byte) (ret []byte, err error) {
	support.CheckSize(nonce, a.NonceSize(), "nonce")
	support.CheckSize(mac, a.Overhead(), "mac")

	ret, m := appendSlices(dst, len(ciphertext))

	exit := C.crypto_aead_aes256gcm_decrypt_detached_afternm(
		(*C.uchar)(support.BytePointer(m)),
		(*C.uchar)(nil),
		(*C.uchar)(support.BytePointer(ciphertext)),
		(C.ulonglong)(len(ciphertext)),
		(*C.uchar)(&mac[0]),
		(*C.uchar)(support.BytePointer(additionalData)),
		(C.ulonglong)(len(additionalData)),
		(*C.uchar)(&nonce[0]),
		a.state())

	if exit != 0 {
		err = &support.VerificationError{}
	}

	return
}
