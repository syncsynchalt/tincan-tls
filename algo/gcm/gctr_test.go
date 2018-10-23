package gcm

import (
	"testing"
	"encoding/hex"

	"github.com/syncsynchalt/tincan-tls/algo/aes"
)

func copyBytes(b []byte) []byte {
	return append([]byte(nil), b...)
}

func TestGctrIndependent(t *testing.T) {
	key := []byte{0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	t.Log("key:", hex.EncodeToString(key))

	x := make([]byte, 48)
	x[0] = 1; x[16] = 2; x[32] = 3
	t.Log("plaintext:", hex.EncodeToString(x))

	icb  := []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	t.Log("icb:", hex.EncodeToString(icb))

	// found using openssl enc command line tool
	ccb1, _ := hex.DecodeString("fc7a6d88a672b5fab0f2f1982c7851b9")
	ccb2, _ := hex.DecodeString("d51377c6d7b957ba75f5f9525589a4ff")
	ccb3, _ := hex.DecodeString("51ce5e4c40546a0d88a908955faff973")
	xor(ccb1, x[0:16])
	xor(ccb2, x[16:32])
	xor(ccb3, x[32:48])
	expect := ccb1
	expect = append(expect, ccb2...)
	expect = append(expect, ccb3...)

	cipher := aes.New128(key)
	result := gctr(cipher, icb, x)
	equals(t, expect, result)
}

func expectedResult(key, icb, plaintext []byte) []byte {
	cipher := aes.New128(key)
	expected := make([]byte, 0)
	scratch := make([]byte, 16)
	cb := copyBytes(icb)

	for len(plaintext) > 0 {
		ccb := copyBytes(cipher.Cipher(cb))
		l := 16
		if len(plaintext) < 16 {
			l = len(plaintext)
		}
		copy(scratch, plaintext)
		xor(ccb, scratch)
		expected = append(expected, ccb[:l]...)

		inc_32(cb)
		plaintext = plaintext[l:]
	}
	return expected
}

func TestGctrFullBlock(t *testing.T) {
	key := []byte{10, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31, 32, 33, 34, 35}

	x := make([]byte, 48)
	for i := range x {
		x[i] = byte(i)
	}
	t.Log("plaintext:", hex.EncodeToString(x))

	icb  := []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	t.Log("icb:", hex.EncodeToString(icb))

	expect := expectedResult(key, icb, x)

	cipher := aes.New128(key)
	result := gctr(cipher, icb, x)
	equals(t, expect, result)
}

func TestGctrPartBlocks(t *testing.T) {
	key := []byte{10, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31, 32, 33, 34, 35}
	cipher := aes.New128(key)

	x := make([]byte, 1024)
	for i := range x {
		x[i] = byte(i)
	}

	icb  := []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	for i := 0; i < 32; i++ {
		t.Log("testing plaintext of", len(x), "bytes")
		expect := expectedResult(key, icb, x)
		result := gctr(cipher, icb, x)
		equals(t, expect, result)
		x = x[:len(x)-1]
	}
}
