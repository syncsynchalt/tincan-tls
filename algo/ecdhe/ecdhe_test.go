package ecdhe_test

import (
	"testing"

	"encoding/hex"
	"github.com/syncsynchalt/tincan-tls/algo/ecdhe"
	"time"
)

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
