package gcm

import (
	"testing"
)

func TestGHashOne(t *testing.T) {
	a := make16([]byte{1})
	h := make16([]byte{2})

	result := ghash(h, a)

	// X1•Hm ⊕ X2•Hm-1 ⊕ ... ⊕ Xm-1•H2 ⊕ Xm•H
	calc1 := multBlocks(a, h)
	equals(t, calc1, result)
}

func TestGHashTwo(t *testing.T) {
	a := make16([]byte{1})
	b := make16([]byte{2})
	c := a
	c = append(c, b...)
	h := make16([]byte{0x10, 0x20, 0x30})
	h2 := multBlocks(h, h)

	result := ghash(h, c)

	// X1•Hm ⊕ X2•Hm-1 ⊕ ... ⊕ Xm-1•H2 ⊕ Xm•H
	calc1 := multBlocks(a, h2)
	calc_ := multBlocks(b, h)
	xor(calc1, calc_)
	equals(t, calc1, result)
}

func TestGHashMult(t *testing.T) {
	a := make16([]byte{1})
	b := make16([]byte{2})
	c := make16([]byte{3})
	d := a
	d = append(d, b...)
	d = append(d, c...)
	h1 := make16([]byte{0x16, 0x20, 0x3f})
	h2 := multBlocks(h1, h1)
	h3 := multBlocks(h2, h1)

	result := ghash(h1, d)

	// X1•Hm ⊕ X2•Hm-1 ⊕ ... ⊕ Xm-1•H2 ⊕ Xm•H
	calc1 := multBlocks(a, h3)
	calc2 := multBlocks(b, h2)
	calc3 := multBlocks(c, h1)
	xor(calc1, calc2)
	xor(calc1, calc3)
	equals(t, calc1, result)
}
