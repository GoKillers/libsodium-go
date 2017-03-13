package cryptostream

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"

func CryptoStreamKeyBytes() int {
	return int(C.crypto_stream_keybytes())
}

func  CryptoStreamNonceBytes() int {
	return int(C.crypto_stream_noncebytes())
}

func CryptoStreamPrimitive() string {
	return C.GoString(C.crypto_stream_primitive())
}

func CryptoStream(clen int, n []byte, k []byte) ([]byte, int) {
	support.CheckSize(n, CryptoStreamNonceBytes(), "nonce")
	support.CheckSize(k, CryptoStreamKeyBytes(), "key")
	return CryptoStreamXSalsa20(clen, n, k)
}

func CryptoStreamXOR(m []byte, n []byte, k []byte) ([]byte, int) {
	support.CheckSize(n, CryptoStreamNonceBytes(), "nonce")
	support.CheckSize(k, CryptoStreamKeyBytes(), "key")
	return CryptoStreamXSalsa20XOR(m, n, k)
}
