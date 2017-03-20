package cryptostream

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"

func CryptoStreamChaCha20KeyBytes() int {
	return int(C.crypto_stream_chacha20_keybytes())
}

func CryptoStreamChaCha20NonceBytes() int {
	return int(C.crypto_stream_chacha20_noncebytes())
}

func CryptoStreamChaCha20(clen int, n []byte, k []byte) ([]byte, int) {
	support.CheckSize(n, CryptoStreamChaCha20NonceBytes(), "nonce")
	support.CheckSize(k, CryptoStreamChaCha20KeyBytes(), "key")
	c := make([]byte, clen)
	exit := int(C.crypto_stream_chacha20(
		(*C.uchar)(&c[0]),
		(C.ulonglong)(clen),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0])))

	return c, exit
}

func CryptoStreamChaCha20XOR(m []byte, n []byte, k []byte) ([]byte, int) {
	support.CheckSize(n, CryptoStreamChaCha20NonceBytes(), "nonce")
	support.CheckSize(k, CryptoStreamChaCha20KeyBytes(), "key")
	c := make([]byte, len(m))
	exit := int(C.crypto_stream_chacha20_xor(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0])))

	return c, exit
}

func CryptoStreamChaCha20XORIC(m []byte, n []byte, ic uint64, k []byte) ([]byte, int) {
	support.CheckSize(n, CryptoStreamChaCha20NonceBytes(), "nonce")
	support.CheckSize(k, CryptoStreamChaCha20KeyBytes(), "key")

	c := make([]byte, len(m))
	exit := int(C.crypto_stream_chacha20_xor_ic(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(C.uint64_t)(ic),
		(*C.uchar)(&k[0])))

	return c, exit
}

func CryptoStreamChaCha20Keygen() []byte {
	c := make([]byte, CryptoStreamChaCha20KeyBytes())
	C.crypto_stream_chacha20_keygen((*C.uchar)(&c[0]))
	return c
}

func CryptoStreamChaCha20IETFKeyBytes() int {
	return int(C.crypto_stream_chacha20_ietf_keybytes())
}

func CryptoStreamChaCha20IETFNonceBytes() int {
	return int(C.crypto_stream_chacha20_ietf_noncebytes())
}

func CryptoStreamChaCha20IETF(clen int, n []byte, k []byte) ([]byte, int) {
	support.CheckSize(n, CryptoStreamChaCha20IETFNonceBytes(), "nonce")
	support.CheckSize(k, CryptoStreamChaCha20IETFKeyBytes(), "key")
	c := make([]byte, clen)
	exit := int(C.crypto_stream_chacha20_ietf(
		(*C.uchar)(&c[0]),
		(C.ulonglong)(clen),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0])))

	return c, exit
}

func CryptoStreamChaCha20IETFXOR(m []byte, n []byte, k []byte) ([]byte, int) {
	support.CheckSize(n, CryptoStreamChaCha20IETFNonceBytes(), "nonce")
	support.CheckSize(k, CryptoStreamChaCha20IETFKeyBytes(), "key")
	c := make([]byte, len(m))
	exit := int(C.crypto_stream_chacha20_ietf_xor(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0])))

	return c, exit
}

func CryptoStreamChaCha20IETFXORIC(m []byte, n []byte, ic uint32, k []byte) ([]byte, int) {
	support.CheckSize(n, CryptoStreamChaCha20IETFNonceBytes(), "nonce")
	support.CheckSize(k, CryptoStreamChaCha20IETFKeyBytes(), "key")

	c := make([]byte, len(m))
	exit := int(C.crypto_stream_chacha20_ietf_xor_ic(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(C.uint32_t)(ic),
		(*C.uchar)(&k[0])))

	return c, exit
}

func CryptoStreamChaCha20IETFKeygen() []byte {
	c := make([]byte, CryptoStreamChaCha20IETFKeyBytes())
	C.crypto_stream_chacha20_ietf_keygen((*C.uchar)(&c[0]))
	return c
}
