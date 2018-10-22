package ecdhe_test

import (
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"encoding/hex"
	"github.com/syncsynchalt/tincan-tls/algo/ecdhe"
	"time"
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

func TestCalc(t *testing.T) {
	start := time.Now()
	defer func() { t.Log("took", time.Since(start)) }()

	mykey, mypub, err := ecdhe.GenerateKeys()
	ok(t, err)
	t.Log("mykey:", hex.EncodeToString(mykey))
	t.Log("mypub:", hex.EncodeToString(mypub))

	otherkey, otherpub, err := ecdhe.GenerateKeys()
	ok(t, err)
	t.Log("otherkey:", hex.EncodeToString(otherkey))
	t.Log("otherpub:", hex.EncodeToString(otherpub))

	secret1 := ecdhe.CalculateSharedSecret(mykey, otherpub)
	secret2 := ecdhe.CalculateSharedSecret(otherkey, mypub)
	equals(t, secret1, secret2)
}
