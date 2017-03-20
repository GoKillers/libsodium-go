package cryptostream

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"

func CryptoStreamSalsa208KeyBytes() int {
	return int(C.crypto_stream_salsa208_keybytes())
}

func CryptoStreamSalsa208NonceBytes() int {
	return int(C.crypto_stream_salsa208_noncebytes())
}

func CryptoStreamSalsa208(clen int, n []byte, k []byte) ([]byte, int) {
	support.CheckSize(n, CryptoStreamSalsa208NonceBytes(), "nonce")
	support.CheckSize(k, CryptoStreamSalsa208KeyBytes(), "key")
	c := make([]byte, clen)
	exit := int(C.crypto_stream_salsa208(
		(*C.uchar)(&c[0]),
		(C.ulonglong)(clen),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0])))

	return c, exit
}

func CryptoStreamSalsa208XOR(m []byte, n []byte, k []byte) ([]byte, int) {
	support.CheckSize(n, CryptoStreamSalsa208NonceBytes(), "nonce")
	support.CheckSize(k, CryptoStreamSalsa208KeyBytes(), "key")
	c := make([]byte, len(m))
	exit := int(C.crypto_stream_salsa208_xor(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0])))

	return c, exit
}

func CryptoStreamSalsa208Keygen() []byte {
	c := make([]byte, CryptoStreamSalsa208KeyBytes())
	C.crypto_stream_salsa208_keygen((*C.uchar)(&c[0]))
	return c
}
