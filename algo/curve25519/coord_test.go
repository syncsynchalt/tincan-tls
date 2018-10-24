package curve25519

import (
	"testing"
)

func TestCopy(t *testing.T) {
	a := newCoord(1)
	b := a.copy()
	equals(t, a, b)
	a[0]++
	assert(t, a[0] != b[0], "a and b don't seem to be copies")
}

func TestCoordToHex(t *testing.T) {
	a := newCoord(0)
	equals(t, "0x00000000", a.toHex())

	a = newCoord(1)
	equals(t, "0x00000001", a.toHex())

	a = newCoord(0xff)
	equals(t, "0x000000ff", a.toHex())

	a = newCoord(0xffffffff)
	equals(t, "0xffffffff", a.toHex())
}

func TestCoordAdd(t *testing.T) {
	a := newCoord(0xffffffffffffffff)
	b := newCoord(1)
	c := a.add(b)
	equals(t, "0x00000001_00000000_00000000", c.toHex())
	c = b.add(a)
	equals(t, "0x00000001_00000000_00000000", c.toHex())
}

func TestCoordAddCarry(t *testing.T) {
	a := newCoord(0xffffffffffffffff)
	b := newCoord(0xffffffffffffffff)
	c := a.add(b)
	equals(t, "0x00000001_ffffffff_fffffffe", c.toHex())
}

func TestCoordCompare(t *testing.T) {
	a := newCoord(0)
	b := newCoord(0)
	assert(t, a.compare(b) == 0, "a and b are not seen as equal")
	a = newCoord(1)
	assert(t, a.compare(b) > 0, "a not seen bigger than b")
	assert(t, b.compare(a) < 0, "a not seen bigger than b")

	a = newCoord(1)
	b = newCoord(0xFFFFFFFF)
	b = a.add(b)
	assert(t, b.compare(a) > 0, "a not seen bigger than b")
	assert(t, a.compare(b) < 0, "a not seen bigger than b")
}

func TestCoordRotateSmall(t *testing.T) {
	a := newCoord(0x01020304)
	a = a.rotl(8)
	equals(t, "0x00000001_02030400", a.toHex())
	a = a.rotr(8)
	equals(t, "0x01020304", a.toHex())
	a = a.rotl(4)
	equals(t, "0x10203040", a.toHex())
}

func TestCoordRotateLarge(t *testing.T) {
	a := newCoord(1)
	a = a.rotl(32)
	equals(t, "0x00000001_00000000", a.toHex())
	a = a.rotl(32)
	equals(t, "0x00000001_00000000_00000000", a.toHex())
	a = a.rotl(32)
	equals(t, "0x00000001_00000000_00000000_00000000", a.toHex())
	a = a.rotr(32)
	a = a.rotr(32)
	equals(t, "0x00000001_00000000", a.toHex())
	a = a.rotr(32)
	equals(t, "0x00000001", a.toHex())
	a = a.rotl(40)
	equals(t, "0x00000100_00000000", a.toHex())
	a = a.rotr(40)
	equals(t, "0x00000001", a.toHex())
}

func TestCoordSub(t *testing.T) {
	a := newCoord(10)
	b := newCoord(1)
	c := a.sub(b)
	equals(t, "0x00000009", c.toHex())

	a = newCoord(0)
	c = a.sub(newCoord(2))
	equals(t, "0xffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff"+
		"_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_fffffffe", c.toHex())
}

func TestCoordReduce(t *testing.T) {
	a := newCoord(0)
	a = a.reduce()
	equals(t, "0x00000000", a.toHex())

	a = newCoord(1)
	a = a.reduce()
	equals(t, "0x00000001", a.toHex())

	a = coordModulus.copy()
	a = a.reduce()
	equals(t, "0x00000000", a.toHex())

	a = coordModulus.sub(newCoord(1))
	a = a.reduce()
	equals(t, "0x7fffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffec", a.toHex())

	a = coordModulus.add(newCoord(1))
	a = a.reduce()
	equals(t, "0x00000001", a.toHex())
}

func TestCoordMult(t *testing.T) {
	a := newCoord(1)
	b := newCoord(2)
	c := a.mult(b)
	equals(t, "0x00000002", c.toHex())

	a = newCoord(0xabcd)
	b = newCoord(0x1f)
	c = a.mult(b)
	equals(t, "0x0014cdd3", c.toHex())
}

func TestCoordMultMax(t *testing.T) {
	a := newCoord(0xFFFFFFFF)
	a = a.mult(newCoord(2))
	equals(t, "0x00000001_fffffffe", a.toHex())

	a = newCoord(2)
	a = a.mult(newCoord(0xFFFFFFFF))
	equals(t, "0x00000001_fffffffe", a.toHex())

	a = newCoord(0xFFFFFFFF)
	a = a.mult(a)
	equals(t, "0xfffffffe_00000001", a.toHex())

	a = coordModulus.mult(coordModulus)
	equals(t, "0x3fffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffed"+
		"_00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000169", a.toHex())
}

func TestCoordModMults(t *testing.T) {
	a := newCoord(1).mult(coordModulus)
	equals(t, "0x7fffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffed", a.toHex())
	b := newCoord(2).mult(coordModulus)
	equals(t, "0xffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffda", b.toHex())
	c := newCoord(3).mult(coordModulus)
	equals(t, "0x00000001_7fffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffc7", c.toHex())
	d := newCoord(4).mult(coordModulus)
	equals(t, "0x00000001_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffb4", d.toHex())
}

func TestCoordReduceThree(t *testing.T) {
	a := newCoord(3).mult(coordModulus)
	a = a.reduce()
	equals(t, "0x00000000", a.toHex())
}

func TestCoordMultByAdd(t *testing.T) {
	a := coordModulus.mult(newCoord(3))
	b := coordModulus.mult(newCoord(2))
	b = b.add(coordModulus)
	equals(t, "0x00000000", a.sub(b).toHex())
}

func TestCoordMultCommutative(t *testing.T) {
	a := newCoord(3)
	b := newCoord(0xFFFFFFFFFFFFFFFF)
	c1 := a.mult(b)
	c2 := b.mult(a)
	assert(t, c1.compare(c2) == 0, "c1 and c2 not equal")
	equals(t, "0x00000000", c1.sub(c2).toHex())
}

func TestCoordBigSub(t *testing.T) {
	a := coordModulus.mult(newCoord(3))
	b := coordModulus.rotl(1)
	equals(t, coordModulus, a.sub(b))
}

func TestCoordMaxReduce(t *testing.T) {
	a := coordModulus
	a = a.reduce()
	equals(t, "0x00000000", a.toHex())

	a = coordModulus.mult(newCoord(2))
	a = a.reduce()
	equals(t, "0x00000000", a.toHex())

	a = coordModulus.mult(newCoord(3))
	a = a.reduce()
	equals(t, "0x00000000", a.toHex())

	for i := uint64(0); i < 10; i++ {
		t.Log("Testing", i)
		a = coordModulus.mult(newCoord(i))
		a = a.reduce()
		equals(t, "0x00000000", a.toHex())
	}

	a = coordModulus.mult(coordModulus)
	a = a.reduce()
	equals(t, "0x00000000", a.toHex())
}

func TestCoordNBit(t *testing.T) {
	a := newCoord(5)
	equals(t, 1, a.nbit(0))
	equals(t, 0, a.nbit(1))
	equals(t, 1, a.nbit(2))
	equals(t, 0, a.nbit(3))

	a = a.rotl(128)
	equals(t, 0, a.nbit(0))
	equals(t, 1, a.nbit(128))
	equals(t, 0, a.nbit(129))
	equals(t, 1, a.nbit(130))
}

func TestBytesToCoord(t *testing.T) {
	var b = [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}
	c := bytesToCoord(b)
	equals(t, "0x201f1e1d_1c1b1a19_18171615_14131211_100f0e0d_0c0b0a09_08070605_04030201", c.toHex())
}

func TestCoordToBytes(t *testing.T) {
	var b = [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}
	c := bytesToCoord(b)
	equals(t, b, c.toBytes())
}

func TestCoordReduceNegative(t *testing.T) {
	a := newCoord(0)
	b := newCoord(1)
	c := a.sub(b)
	t.Log("c is", c.toHex())
	d := c.reduce()
	e := coordModulus.sub(newCoord(1))
	equals(t, e, d)
}
