// This is a toy implementation and is full of side channels and other defects.
// DO NOT use this in a real cryptographic application.

// based on RFC 5869

package hkdf

import (
	"github.com/syncsynchalt/tincan-tls/algo/hmac"
)

func Extract(hasher hmac.Hasher, salt, keymaterial []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, hasher.BlockSize())
	}
	return hmac.Compute(salt, keymaterial, hasher)
}

func Expand(hasher hmac.Hasher, keymaterial, info []byte, outlength int) []byte {
	n := (outlength + hasher.HashLen() + 1) / hasher.HashLen()
	result := []byte{}
	T := []byte{}
	for i := 1; i <= n; i++ {
		T = append(T, info...)
		T = append(T, byte(i))
		T = hmac.Compute(keymaterial, T, hasher)
		result = append(result, T...)
	}
	return result[:outlength]
}
