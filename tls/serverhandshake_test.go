package tls

import (
	"testing"
)

func TestReadNum(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	equals(t, uint(1), readNum(8, b))
	equals(t, uint(258), readNum(16, b))
	equals(t, uint(66051), readNum(24, b))
}

func TestReadVec(t *testing.T) {
	b := []byte{0, 0, 1, 2, 3, 4}
	v, rest := readVec(24, b)
	equals(t, []byte{2}, v)
	equals(t, []byte{3, 4}, rest)
}
