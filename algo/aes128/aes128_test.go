package aes128

import (
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func equals(tb testing.TB, exp, act interface{}) {
	if !reflect.DeepEqual(exp, act) {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d:\n\n\texp: %#v\n\n\tgot: %#v\033[39m\n\n", filepath.Base(file), line, exp, act)
		tb.FailNow()
	}
}

// assert fails the test if the condition is false.
func assert(tb testing.TB, condition bool, msg string, v ...interface{}) {
	if !condition {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d: "+msg+"\033[39m\n\n", append([]interface{}{filepath.Base(file), line}, v...)...)
		tb.FailNow()
	}
}

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
	key := []byte("\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c")
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
