package gcm

import (
	"testing"

	"encoding/hex"
)

func inc_str(t *testing.T, s string) (string, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	inc_32(b)
	result := hex.EncodeToString(b)
	return result, nil
}

func TestInc(t *testing.T) {
	s, err := inc_str(t, "01020304")
	ok(t, err)
	equals(t, "01020305", s)

	s, err = inc_str(t, "ffff01020304")
	ok(t, err)
	equals(t, "ffff01020305", s)
}

func TestIncWrap(t *testing.T) {
	s, err := inc_str(t, "ffffffff")
	ok(t, err)
	equals(t, "00000000", s)

	s, err = inc_str(t, "aabbffffffff")
	ok(t, err)
	equals(t, "aabb00000000", s)
}
