package gcm

import (
	"testing"
)

func make16(b []byte) []byte {
	for len(b) < 16 {
		b = append(b, 0)
	}
	return b
}

// test commutative property
func TestCommute(t *testing.T) {
	a := make16([]byte{0x01, 0x02})
	b := make16([]byte{0x02, 0x03})

	c := multBlocks(a, b)
	d := multBlocks(b, a)

	equals(t, c, d)
}

// test distributive property, (a+b)*c == (a*c)+(b*c)
func TestDistrib(t *testing.T) {
	a := make16([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3})
	b := make16([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 4})
	c := make16([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 4, 5})

	aplusb := make16([]byte{})
	copy(aplusb, a)
	xor(aplusb, b)
	d1 := multBlocks(aplusb, c)

	d2 := multBlocks(a, c)
	d_ := multBlocks(b, c)
	xor(d2, d_)

	equals(t, d1, d2)
}

// order of GF(2^128) is 2^128-1, so squaring 128 times should result in identity
func TestOrder(t *testing.T) {
	a := make16([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3})
	b := make16([]byte{})
	copy(b, a)

	t.Log(b)
	for i := 0; i < 128; i++ {
		b = multBlocks(b, b)
		t.Log(b)
	}
	equals(t, a[:], b)
}

func TestTestVector(t *testing.T) {
	a := make16([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	b := make16([]byte{0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0})
	e := make16([]byte{0x91, 0x61, 0x62, 0x9d, 0xe5, 0xfa, 0x86, 0x86, 0x1d, 0xa2, 0xde, 0xde, 0x59, 0xb9, 0x3a, 0xc5})
	c := multBlocks(a, b)
	equals(t, e, c)
}
