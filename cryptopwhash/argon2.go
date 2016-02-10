package cryptopwhash

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import "github.com/GoKillers/libsodium-go/support"

func Argon2iHashRaw(tCost int,
					mCost int,
					parallelism int,
					pwd []byte,
					pwdLen int,
					salt []byte,
					saltLen int,
					hash []byte,
					hashLen int) ([]bye, int) {

	
	h := make([]byte, len(hash))

	exit := int(C.argon2i_hash_raw(
		(*C.ulonglong)(tCost),
		(*C.ulonglong)(mCost),
		(*C.ulonglong)(parallelism),
		(*C.uchar)(&pwd[0]),
		(*C.ulonglong)(len(pwd)),
		(*C.uchar)(&salt[0]),
		(*C.ulonglong)(len(salt)),
		(*C.uchar)(&hash[0]),
		(C.ulonglong)(len(hash))))
		
	return hash, exit
}
