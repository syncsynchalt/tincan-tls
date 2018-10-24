package hmac_test

import (
	"testing"

	"encoding/hex"

	"github.com/syncsynchalt/tincan-tls/algo/hmac"
	"github.com/syncsynchalt/tincan-tls/algo/sha256"
)

func h(sum []byte) string {
	return hex.EncodeToString(sum)
}

func b(s string) []byte {
	return []byte(s)
}

func TestShort(t *testing.T) {
	s := sha256.New()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	data := b("abcd")
	equals(t, "ce5ab0733fe9b6f0767e841868c523e7db0c60d1fe6f276399fdee63d61d6c5b", h(hmac.Compute(key, data, s)))
}

func TestSimple(t *testing.T) {
	s := sha256.New()
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i)
	}
	data := b("abcd")
	equals(t, "7eb364829d5bc45f32c18799e8aa3f23fa86a1aff4e747eae54ce1771b6b2ce2", h(hmac.Compute(key, data, s)))
}

func TestLongKey(t *testing.T) {
	s := sha256.New()
	key := make([]byte, 70)
	for i := range key {
		key[i] = byte(i)
	}
	data := b("abcd")
	equals(t, "1ae43d93e2b3ef5de29a06231bd5c1e2699d62db9cc7457f5b7c2e707bab5b4f", h(hmac.Compute(key, data, s)))
}

func TestPad(t *testing.T) {
	s := sha256.New()
	key := []byte{0x1, 0x2, 0x3, 0x4}
	data := b("abcd")
	equals(t, "a7201c7404c3cebbaa55742e9d3cda4495682d53138192738cf9d26ef4f2422e", h(hmac.Compute(key, data, s)))
}

func TestZeros(t *testing.T) {
	s := sha256.New()
	key := []byte{}
	data := []byte{}
	equals(t, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad", h(hmac.Compute(key, data, s)))
}

func TestLong(t *testing.T) {
	s := sha256.New()
	key := []byte{0x1, 0x2, 0x3, 0x4}
	str := ""
	for i := 0; i < 1000; i++ {
		str += "1234567890"
	}
	data := b(str)
	equals(t, "a726645fabd1dc68c14d07a33de851d7a3a0d86d5c988754e066e8105beb6061", h(hmac.Compute(key, data, s)))
}

// test vectors from RFC 4231
func TestRfcVec1(t *testing.T) {
	s := sha256.New()
	key, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	data := []byte("Hi There")
	expect, _ := hex.DecodeString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
	equals(t, expect, hmac.Compute(key, data, s))
}

func TestRfcVec2(t *testing.T) {
	s := sha256.New()
	key := []byte("Jefe")
	data := []byte("what do ya want for nothing?")
	expect, _ := hex.DecodeString("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
	equals(t, expect, hmac.Compute(key, data, s))
}

func TestRfcVec3(t *testing.T) {
	s := sha256.New()
	key, _ := hex.DecodeString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	data, _ := hex.DecodeString("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" +
		"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")
	expect, _ := hex.DecodeString("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
	equals(t, expect, hmac.Compute(key, data, s))
}
