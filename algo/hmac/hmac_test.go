package hmac_test

import (
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"encoding/hex"

	"github.com/syncsynchalt/tincan-tls/algo/hmac"
	"github.com/syncsynchalt/tincan-tls/algo/sha256"
)

func equals(tb testing.TB, exp, act interface{}) {
	if !reflect.DeepEqual(exp, act) {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d:\n\n\texp: %#v\n\n\tgot: %#v\033[39m\n\n", filepath.Base(file), line, exp, act)
		tb.FailNow()
	}
}

func h(sum []byte) string {
	return hex.EncodeToString(sum)
}

func b(s string) []byte {
	return []byte(s)
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
	equals(t, "7eb364829d5bc45f32c18799e8aa3f23fa86a1aff4e747eae54ce1771b6b2ce2", h(hmac.Compute(key, data, s)))
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
