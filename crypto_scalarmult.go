package nacl

// #cgo CFLAGS: -I/usr/local/include/sodium
// #cgo LDFLAGS: /usr/local/lib/libsodium.a
// #include <stdio.h>
// #include <sodium.h>
import "C"

func CryptoScalarmultBytes() int {
	return int(C.crypto_scalarmult_bytes())
}

func CryptoScalarmultScalarBytes() int {
	return int(C.crypto_scalarmult_scalarbytes())
}

func CryptoScalarmultPrimitive() string {
	return C.GoString(C.crypto_scalarmult_primitive())
}

func CryptoScalarmultBase(n []byte) ([]byte, int) {
	checkSize(n, CryptoScalarmultScalarBytes(), "secret key")
	q := make([]byte, CryptoScalarmultBytes())
	exit := C.crypto_scalarmult_base(
		(*C.uchar)(&q[0]),
		(*C.uchar)(&n[0]))

	return q, exit
}

func CryptoScalarMult(n []byte, p []byte) ([]byte, int) {
	checkSize(n, CryptoScalarmultScalarBytes(), "secret key")
	checkSize(p, CryptoScalarmultScalarBytes(), "public key")
	q := make([]byte, CryptoScalarmultBytes())
	exit := C.crypto_scalarmult(
		(*C.uchar)(&q[0]),
		(*C.uchar)(&n[0]),
		(*C.uchar)(&p[0]))

	return q, exit

}

func checkSize(buf []byte, expected int, descrip string) {
	if len(buf) != expected {
		panic(fmt.Sprintf("Incorrect %s buffer size, expected (%d), got (%d).", descrip, expected, len(buf)))
	}
}
