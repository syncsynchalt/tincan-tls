package curve25519

import (
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"encoding/hex"
)

// equals fails the test if exp is not equal to act.
func equals(tb testing.TB, exp, act interface{}) {
	if !reflect.DeepEqual(exp, act) {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d:\n\n\texp: %#v\n\n\tgot: %#v\033[39m\n\n", filepath.Base(file), line, exp, act)
		tb.FailNow()
	}
}

// ok fails the test if an err is not nil.
func ok(tb testing.TB, err error) {
	if err != nil {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d: unexpected error: %s\033[39m\n\n", filepath.Base(file), line, err.Error())
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

func TestSwap(t *testing.T) {
	a := newCoord(1)
	b := newCoord(2)

	a, b = cswap(1, a, b)
	equals(t, newCoord(1), b)
	equals(t, newCoord(2), a)

	a, b = cswap(0, a, b)
	equals(t, newCoord(1), b)
	equals(t, newCoord(2), a)
}

func TestMult(t *testing.T) {
	var key = [32]byte {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}
	var expect = [32]byte {
		0x07, 0xa3, 0x7c, 0xbc, 0x14, 0x20, 0x93, 0xc8, 0xb7, 0x55, 0xdc, 0x1b, 0x10, 0xe8, 0x6c, 0xb4,
		0x26, 0x37, 0x4a, 0xd1, 0x6a, 0xa8, 0x53, 0xed, 0x0b, 0xdf, 0xc0, 0xb2, 0xb8, 0x6d, 0x1c, 0x7c,
	}

	out := Mult(key, u_nine_bytes)
	equals(t, expect, out)
}

func TestKeyPair(t *testing.T) {
	priv, pub, err := KeyPair()
	ok(t, err)

	t.Log("private key:", hex.EncodeToString(priv[:]))
	t.Log(" public key:", hex.EncodeToString(pub[:]))
}
