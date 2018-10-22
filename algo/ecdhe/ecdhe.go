// This is a toy implementation and is full of side channels and other defects.
// DO NOT use this in a real cryptographic application.

// based on RFC 4492

package ecdhe

import (
	"github.com/syncsynchalt/tincan-tls/algo/curve25519"
)

func GenerateKeys() (privkey, pubkey []byte, err error) {
	key, pub, err := curve25519.KeyPair()
	if err != nil {
		return nil, nil, err
	}
	return key[:], pub[:], err
}

func CalculateSharedSecret(mykey, otherpub []byte) []byte {
	var k, p [32]byte
	copy(k[:], mykey)
	copy(p[:], otherpub)
	secret := curve25519.Mult(k, p)
	return secret[:]
}
