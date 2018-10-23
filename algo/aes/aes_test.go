package aes

import (
	"testing"

	"encoding/hex"
)

func TestMult(t *testing.T) {
	equals(t, byte(0x01), rjmult(0x53, 0xca))
	equals(t, byte(0xc1), rjmult(0x57, 0x83))
	equals(t, byte(0x2), rjmult(0x01, 0x02))
	equals(t, byte(0x4), rjmult(0x02, 0x02))
}

func TestAllInverse(t *testing.T) {
	for i := 0; i < 256; i++ {
		t.Log("testing", i)
		j := findInverse(byte(i))
		t.Log("got", j)
	}
}

func TestSBoxAffine(t *testing.T) {
	equals(t, byte(0x63), sboxAffine(0x00))
	equals(t, byte(0x7c), sboxAffine(0x01))
	equals(t, byte(0x77), sboxAffine(0x8d))
	equals(t, byte(0x53), sboxAffine(0xed))
}

func TestSBox(t *testing.T) {
	sbox := generateSBox()
	t.Log("SBox:")
	for i := 0; i < 16; i++ {
		s := sbox[i*16 : (i+1)*16]
		t.Logf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15])
	}

	xy := func(x, y int) byte {
		return sbox[y+16*x]
	}
	equals(t, byte(0x63), xy(0x0, 0x0))
	equals(t, byte(0x76), xy(0x0, 0xF))
	equals(t, byte(0x49), xy(0xA, 0x4))
	equals(t, byte(0x16), xy(0xF, 0xF))

	chk := make([]bool, 256)
	for i := range sbox {
		assert(t, chk[sbox[i]] == false, "bit %d is already set", i)
		chk[sbox[i]] = true
	}
}

func TestSubWord(t *testing.T) {
	equals(t, uint32(0x777d3696), subWord(0x02132435))
}

func TestRotWord(t *testing.T) {
	equals(t, uint32(0x02030401), rotWord(0x01020304))
	equals(t, uint32(0xfdfefffc), rotWord(0xfcfdfeff))
}

func TestKeyExpansion(t *testing.T) {
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	w := keyExpansion(key)
	t.Log("Key Expansion:")
	for i := 0; i < len(w)/4; i++ {
		z := w[i*4 : (i+1)*4]
		t.Logf("%08x %08x %08x %08x\n", z[0], z[1], z[2], z[3])
	}
	equals(t, len(w), 44)
	equals(t, uint32(0x2b7e1516), w[0])
	equals(t, uint32(0x7a96b943), w[9])
	equals(t, uint32(0xb6630ca6), w[43])
}

func TestSubBytes(t *testing.T) {
	b, _ := hex.DecodeString("01102144")
	e, _ := hex.DecodeString("7ccafd1b")
	subBytes(b)
	equals(t, e, b)

	b, _ = hex.DecodeString("00102030405060708090a0b0c0d0e0f0")
	e, _ = hex.DecodeString("63cab7040953d051cd60e0e7ba70e18c")
	subBytes(b)
	equals(t, e, b)
}

func TestAddRoundKey(t *testing.T) {
	b, _ := hex.DecodeString("013c7dff020405089799abc066770110")
	w := []uint32{0x2000000, 0xffffffff, 0x23456789, 0xabcdef01}
	e, _ := hex.DecodeString("033c7dfffdfbfaf7b4dccc49cdbaee11")
	addRoundKey(b, w)
	equals(t, e, b)

	b, _ = hex.DecodeString("00112233445566778899aabbccddeeff")
	w = []uint32{0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f}
	e, _ = hex.DecodeString("00102030405060708090a0b0c0d0e0f0")
	addRoundKey(b, w)
	equals(t, e, b)
}

func TestShiftRows(t *testing.T) {
	// 63cab704 0953d051 cd60e0e7 ba70e18c ->
	// 6353e08c 0960e104 cd70b751 bacad0e7
	b, _ := hex.DecodeString("63cab7040953d051cd60e0e7ba70e18c")
	e, _ := hex.DecodeString("6353e08c0960e104cd70b751bacad0e7")
	shiftRows(b)
	equals(t, e, b)
}

func TestMixColumns(t *testing.T) {
	b, _ := hex.DecodeString("6353e08c0960e104cd70b751bacad0e7")
	e, _ := hex.DecodeString("5f72641557f5bc92f7be3b291db9f91a")
	mixColumns(b)
	equals(t, e, b)

	b, _ = hex.DecodeString("a7be1a6997ad739bd8c9ca451f618b61")
	e, _ = hex.DecodeString("ff87968431d86a51645151fa773ad009")
	mixColumns(b)
	equals(t, e, b)

	b, _ = hex.DecodeString("3bd92268fc74fb735767cbe0c0590e2d")
	e, _ = hex.DecodeString("4c9c1e66f771f0762c3f868e534df256")
	mixColumns(b)
	equals(t, e, b)

	b, _ = hex.DecodeString("2d6d7ef03f33e334093602dd5bfb12c7")
	e, _ = hex.DecodeString("6385b79ffc538df997be478e7547d691")
	mixColumns(b)
	equals(t, e, b)

	b, _ = hex.DecodeString("36339d50f9b539269f2c092dc4406d23")
	e, _ = hex.DecodeString("f4bcd45432e554d075f1d6c51dd03b3c")
	mixColumns(b)
	equals(t, e, b)
}

func TestCipher(t *testing.T) {
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	in, _ := hex.DecodeString("3243f6a8885a308d313198a2e0370734")
	e, _ := hex.DecodeString("3925841d02dc09fbdc118597196a0b32")
	out := make([]byte, 16)
	w := keyExpansion(key)
	cipher(in, out, w)
	equals(t, e, out)

	// repeat to ensure everything's intact
	cipher(in, out, w)
	equals(t, e, out)
}

func TestCipherIndependent(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	in := []byte("abcdefghijklmnop")
	e, _ := hex.DecodeString("d25363fc721337648a68f34abef3b405")

	out := make([]byte, 16)
	w := keyExpansion(key)
	cipher(in, out, w)
	equals(t, e, out)
}

func TestInterface(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	e, _ := hex.DecodeString("d25363fc721337648a68f34abef3b405")

	a := New128(key)
	equals(t, 16, a.KeySize())
	equals(t, 16, a.BlockSize())
	out := make([]byte, a.BlockSize())
	a.Encrypt([]byte("abcdefghijklmnop"), out)
	equals(t, e, out)

	e, _ = hex.DecodeString("8bd658946c56fee7598ce6e41544b92b")
	a.Encrypt([]byte("qrstuvwxyz012345"), out)
	equals(t, e, out)
}

func TestFromCLI(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	e, _ := hex.DecodeString("e37cd363dd7c87a09aff0e3e60e09c82")
	in, _ := hex.DecodeString("01000000000000000000000000000000")

	a := New128(key)
	out := make([]byte, a.BlockSize())
	a.Encrypt(in, out)
	equals(t, e, out)
}
