package cryptoaead

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
	"github.com/GoKillers/libsodium-go/support"
	"unsafe"
)

func CryptoAEADAES256GCMIsAvailable() bool {
	C.sodium_init()
	return int(C.crypto_aead_aes256gcm_is_available()) != 0
}

func CryptoAEADAES256GCMKeyBytes() int {
	return int(C.crypto_aead_aes256gcm_keybytes())
}

func CryptoAEADAES256GCMNSecBytes() int {
	return int(C.crypto_aead_aes256gcm_nsecbytes())
}

func CryptoAEADAES256GCMNPubBytes() int {
	return int(C.crypto_aead_aes256gcm_npubbytes())
}

func CryptoAEADAES256GCMABytes() int {
	return int(C.crypto_aead_aes256gcm_abytes())
}

func CryptoAEADAES256GCMStateBytes() int {
	return int(C.crypto_aead_aes256gcm_statebytes())
}

func CryptoAEADAES256GCMEncrypt(m, ad, npub, k []byte) ([]byte, int) {
	support.CheckSize(k, CryptoAEADAES256GCMKeyBytes(), "secret key")
	support.CheckSize(npub, CryptoAEADAES256GCMNPubBytes(), "public nonce")

	c := make([]byte, len(m)+CryptoAEADAES256GCMABytes())
	cLen := C.ulonglong(len(c))

	exit := int(C.crypto_aead_aes256gcm_encrypt(
		(*C.uchar)(support.BytePointer(c)),
		(*C.ulonglong)(&cLen),
		(*C.uchar)(support.BytePointer(m)),
		(C.ulonglong)(len(m)),
		(*C.uchar)(support.BytePointer(ad)),
		(C.ulonglong)(len(ad)),
		(*C.uchar)(nil),
		(*C.uchar)(&npub[0]),
		(*C.uchar)(&k[0])))

	return c, exit
}

func CryptoAEADAES256GCMDecrypt(c, ad, npub, k []byte) ([]byte, int) {
	support.CheckSize(k, CryptoAEADAES256GCMKeyBytes(), "secret key")
	support.CheckSize(npub, CryptoAEADAES256GCMNPubBytes(), "public nonce")
	support.CheckSizeMin(c, CryptoAEADAES256GCMABytes(), "ciphertext")

	m := make([]byte, len(c)-CryptoAEADAES256GCMABytes())
	mLen := (C.ulonglong)(len(m))

	exit := int(C.crypto_aead_aes256gcm_decrypt(
		(*C.uchar)(support.BytePointer(m)),
		(*C.ulonglong)(&mLen),
		(*C.uchar)(nil),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(support.BytePointer(ad)),
		(C.ulonglong)(len(ad)),
		(*C.uchar)(&npub[0]),
		(*C.uchar)(&k[0])))

	return m, exit
}

func CryptoAEADAES256GCMEncryptDetached(m, ad, npub, k []byte) ([]byte, []byte, int) {
	support.CheckSize(k, CryptoAEADAES256GCMKeyBytes(), "secret key")
	support.CheckSize(npub, CryptoAEADAES256GCMNPubBytes(), "public nonce")

	c := make([]byte, len(m))
	mac := make([]byte , CryptoAEADAES256GCMABytes())
	macLen := C.ulonglong(len(c))

	exit := int(C.crypto_aead_aes256gcm_encrypt_detached(
		(*C.uchar)(support.BytePointer(c)),
		(*C.uchar)(&mac[0]),
		(*C.ulonglong)(&macLen),
		(*C.uchar)(support.BytePointer(m)),
		(C.ulonglong)(len(m)),
		(*C.uchar)(support.BytePointer(ad)),
		(C.ulonglong)(len(ad)),
		(*C.uchar)(nil),
		(*C.uchar)(&npub[0]),
		(*C.uchar)(&k[0])))

	return c, mac, exit
}

func CryptoAEADAES256GCMDecryptDetached(c, mac, ad, npub, k []byte) ([]byte, int) {
	support.CheckSize(k, CryptoAEADAES256GCMKeyBytes(), "secret key")
	support.CheckSize(npub, CryptoAEADAES256GCMNPubBytes(), "public nonce")
	support.CheckSize(mac, CryptoAEADAES256GCMABytes(), "mac")

	m := make([]byte, len(c))

	exit := int(C.crypto_aead_aes256gcm_decrypt_detached(
		(*C.uchar)(support.BytePointer(m)),
		(*C.uchar)(nil),
		(*C.uchar)(support.BytePointer(c)),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&mac[0]),
		(*C.uchar)(support.BytePointer(ad)),
		(C.ulonglong)(len(ad)),
		(*C.uchar)(&npub[0]),
		(*C.uchar)(&k[0])))

	return m, exit
}

func CryptoAEADAES256GCMBeforeNM(k []byte) ([]byte, int) {
	support.CheckSize(k, CryptoAEADAES256GCMKeyBytes(), "secret key")

	ctx := support.AlignedSlice(CryptoAEADAES256GCMStateBytes(), 16)

	exit := int(C.crypto_aead_aes256gcm_beforenm(
		(*C.crypto_aead_aes256gcm_state)(unsafe.Pointer(&ctx[0])),
		(*C.uchar)(&k[0])))

	return ctx, exit
}

func CryptoAEADAES256GCMEncryptAfterNM(m, ad, npub, ctx []byte) ([]byte, int) {
	support.CheckSize(ctx, CryptoAEADAES256GCMStateBytes(), "context")
	support.CheckSize(npub, CryptoAEADAES256GCMNPubBytes(), "public nonce")

	c := make([]byte, len(m)+CryptoAEADAES256GCMABytes())
	cLen := C.ulonglong(len(c))

	exit := int(C.crypto_aead_aes256gcm_encrypt_afternm(
		(*C.uchar)(support.BytePointer(c)),
		(*C.ulonglong)(&cLen),
		(*C.uchar)(support.BytePointer(m)),
		(C.ulonglong)(len(m)),
		(*C.uchar)(support.BytePointer(ad)),
		(C.ulonglong)(len(ad)),
		(*C.uchar)(nil),
		(*C.uchar)(&npub[0]),
		(*[512]C.uchar)(unsafe.Pointer(&ctx[0]))))

	return c, exit
}

func CryptoAEADAES256GCMDecryptAfterNM(c, ad, npub, ctx []byte) ([]byte, int) {
	support.CheckSize(ctx, CryptoAEADAES256GCMStateBytes(), "context")
	support.CheckSize(npub, CryptoAEADAES256GCMNPubBytes(), "public nonce")
	support.CheckSizeMin(c, CryptoAEADAES256GCMABytes(), "ciphertext")

	m := make([]byte, len(c)-CryptoAEADAES256GCMABytes())
	mLen := (C.ulonglong)(len(m))

	exit := int(C.crypto_aead_aes256gcm_decrypt_afternm(
		(*C.uchar)(support.BytePointer(m)),
		(*C.ulonglong)(&mLen),
		(*C.uchar)(nil),
		(*C.uchar)(&c[0]),
		(C.ulonglong)(len(c)),
		(*C.uchar)(support.BytePointer(ad)),
		(C.ulonglong)(len(ad)),
		(*C.uchar)(&npub[0]),
		(*[512]C.uchar)(unsafe.Pointer(&ctx[0]))))

	return m, exit
}

func CryptoAEADAES256GCMEncryptDetachedAfterNM(m, ad, npub, ctx []byte) ([]byte, []byte, int) {
	support.CheckSize(ctx, CryptoAEADAES256GCMStateBytes(), "context")
	support.CheckSize(npub, CryptoAEADAES256GCMNPubBytes(), "public nonce")

	c := make([]byte, len(m))
	mac := make([]byte , CryptoAEADAES256GCMABytes())
	macLen := C.ulonglong(len(c))

	exit := int(C.crypto_aead_aes256gcm_encrypt_detached_afternm(
		(*C.uchar)(support.BytePointer(c)),
		(*C.uchar)(&mac[0]),
		(*C.ulonglong)(&macLen),
		(*C.uchar)(support.BytePointer(m)),
		(C.ulonglong)(len(m)),
		(*C.uchar)(support.BytePointer(ad)),
		(C.ulonglong)(len(ad)),
		(*C.uchar)(nil),
		(*C.uchar)(&npub[0]),
		(*[512]C.uchar)(unsafe.Pointer(&ctx[0]))))

	return c, mac, exit
}

func CryptoAEADAES256GCMDecryptDetachedAfterNM(c, mac, ad, npub, ctx []byte) ([]byte, int) {
	support.CheckSize(ctx, CryptoAEADAES256GCMStateBytes(), "context")
	support.CheckSize(npub, CryptoAEADAES256GCMNPubBytes(), "public nonce")
	support.CheckSize(mac, CryptoAEADAES256GCMABytes(), "mac")

	m := make([]byte, len(c))

	exit := int(C.crypto_aead_aes256gcm_decrypt_detached_afternm(
		(*C.uchar)(support.BytePointer(m)),
		(*C.uchar)(nil),
		(*C.uchar)(support.BytePointer(c)),
		(C.ulonglong)(len(c)),
		(*C.uchar)(&mac[0]),
		(*C.uchar)(support.BytePointer(ad)),
		(C.ulonglong)(len(ad)),
		(*C.uchar)(&npub[0]),
		(*[512]C.uchar)(unsafe.Pointer(&ctx[0]))))

	return m, exit
}

func CryptoAEADAES256GCMKeyGen() []byte {
	k := make([]byte, CryptoAEADAES256GCMKeyBytes())
	C.crypto_aead_aes256gcm_keygen((*C.uchar)(&k[0]))
	return k
}
