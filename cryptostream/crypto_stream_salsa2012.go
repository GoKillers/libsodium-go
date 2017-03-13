package cryptostream

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"

func CryptoStreamSalsa2012KeyBytes() int {
	return int(C.crypto_stream_salsa2012_keybytes())
}

func CryptoStreamSalsa2012NonceBytes() int {
	return int(C.crypto_stream_salsa2012_noncebytes())
}

func CryptoStreamSalsa2012(clen int, n []byte, k []byte) ([]byte, int) {
	support.CheckSize(n, CryptoStreamSalsa2012NonceBytes(), "nonce")
	support.CheckSize(k, CryptoStreamSalsa2012KeyBytes(), "key")
	c := make([]byte, clen)
	exit := int(C.crypto_stream_salsa2012(
		(*C.uchar)(&c[0]),
		(C.ulonglong)(clen),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0])))

	return c, exit
}

func CryptoStreamSalsa2012XOR(m []byte, n []byte, k []byte) ([]byte, int) {
	support.CheckSize(n, CryptoStreamSalsa2012NonceBytes(), "nonce")
	support.CheckSize(k, CryptoStreamSalsa2012KeyBytes(), "key")
	c := make([]byte, len(m))
	exit := int(C.crypto_stream_salsa2012_xor(
		(*C.uchar)(&c[0]),
		(*C.uchar)(&m[0]),
		(C.ulonglong)(len(m)),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&k[0])))

	return c, exit
}

func CryptoStreamSalsa2012Keygen() []byte {
	c := make([]byte, CryptoStreamSalsa2012KeyBytes())
	C.crypto_stream_salsa2012_keygen((*C.uchar)(&c[0]))
	return c
}
