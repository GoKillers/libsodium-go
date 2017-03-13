package cryptostream

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"

func CryptoStreamXChaCha20KeyBytes() int {
	return int(C.crypto_stream_xchacha20_keybytes())
}

func CryptoStreamXChaCha20NonceBytes() int {
	return int(C.crypto_stream_xchacha20_noncebytes())
}

func CryptoStreamXChaCha20(clen int, n []byte, k []byte) ([]byte, int) {
	support.CheckSize(n, CryptoStreamXChaCha20NonceBytes(), "nonce")
	support.CheckSize(k, CryptoStreamXChaCha20KeyBytes(), "key")
	c := make([]byte, clen)
	exit := int(C.crypto_stream_xchacha20(
		(*C.uchar)(&c[0]),
		(C.ulonglong)(clen),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0])))

	return c, exit
}

func CryptoStreamXChaCha20XOR(m []byte, n []byte, k []byte) ([]byte, int) {
	support.CheckSize(n, CryptoStreamXChaCha20NonceBytes(), "nonce")
	support.CheckSize(k, CryptoStreamXChaCha20KeyBytes(), "key")
	c := make([]byte, len(m))
	exit := int(C.crypto_stream_xchacha20_xor(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0])))

	return c, exit
}

func CryptoStreamXChaCha20XORIC(m []byte, n []byte, ic uint64, k []byte) ([]byte, int) {
	support.CheckSize(n, CryptoStreamXChaCha20NonceBytes(), "nonce")
	support.CheckSize(k, CryptoStreamXChaCha20KeyBytes(), "key")

	c := make([]byte, len(m))
	exit := int(C.crypto_stream_xchacha20_xor_ic(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(C.uint64_t)(ic),
		(*C.uchar)(&k[0])))

	return c, exit
}

func CryptoStreamXChaCha20Keygen() []byte {
	c := make([]byte, CryptoStreamXChaCha20KeyBytes())
	C.crypto_stream_xchacha20_keygen((*C.uchar)(&c[0]))
	return c
}
