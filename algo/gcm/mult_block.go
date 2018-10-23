package gcm

var r = []byte{0xe1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,}

func multBlocks(X, Y []byte) []byte {
	if len(X) != 16 || len(Y) != 16 {
		panic("multBlocks bad block length")
	}
	Z := make([]byte, 16)
	V := make([]byte, 16)
	Zero := make([]byte, 16)
	copy(V[:], Y)
	for i := 0; i < 128; i++ {
		if bit(X, i) == 0 {
			xor(Z, Zero)
		} else {
			xor(Z, V)
		}
		lv := bit(V, 127) != 0
		shiftr(V)
		if lv {
			xor(V, r)
		} else {
			xor(V, Zero)
		}
	}
	return Z
}

// where 0 is the first bit, ie. most significant in BE terms
func bit(b []byte, bitnum int) byte {
	i := uint(0)
	for bitnum >= 8 {
		i++
		bitnum -= 8
	}
	return b[i] >> uint(7-bitnum) & 1
}

func xor(dst, xad []byte) {
	if len(dst) != len(xad) {
		panic("xor mismatch len")
	}
	for i := range dst {
		dst[i] = dst[i] ^ xad[i]
	}
}

func shiftr(b []byte) {
	carry := byte(0)
	for i := range b {
		newcarry := b[i] & 1
		b[i] >>= 1
		b[i] |= carry << 7
		carry = newcarry
	}
}
