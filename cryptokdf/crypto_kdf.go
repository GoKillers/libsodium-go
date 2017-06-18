package cryptokdf

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"

func CryptoKdfKeybytes() int {
	return int(C.crypto_kdf_keybytes())
}

func CryptoKdfContextbytes() int {
	return int(C.crypto_kdf_contextbytes())
}

func CryptoKdfBytesMin() int {
	return int(C.crypto_kdf_bytes_min())
}

func CryptoKdfBytesMax() int {
	return int(C.crypto_kdf_bytes_max())
}

func CryptoKdfKeygen(k []byte) {
	support.CheckSize(k, CryptoKdfKeybytes(), "keybytes")
	C.crypto_kdf_keygen((*C.uchar)(&k[0]))
}

func CryptoKdfDeriveFromKey(l int, i uint64, c string, k []byte) ([]byte, int) {
	support.CheckSize(k, CryptoKdfKeybytes(), "keybytes")
	support.CheckSize([]byte(c), CryptoKdfContextbytes(), "contextbytes")
	support.CheckSizeInRange(l, CryptoKdfBytesMin(), CryptoKdfBytesMax(), "subkey_len")
	out := make([]byte, l)

	exit := int(C.crypto_kdf_derive_from_key(
		(*C.uchar)(&out[0]),
		(C.size_t)(l),
		(C.uint64_t)(i),
		C.CString(c),
		(*C.uchar)(&k[0])))

	return out, exit
}
