package curve25519

// this package implements 256-bit math with a modulus of 2^255-19

// little-endian x-value on the 25519 curve
type coord [9]uint64

var coordModulus = coord{
	0xFFFFFFFFFFFFFFED, 0xFFFFFFFFFFFFFFFF,
	0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF,
}

func newCoord(num uint64) coord {
	return coord{num}
}

func bytesToCoord(b [32]byte) coord {
	c := coord{}
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			c[i] |= uint64(b[i*8+j]) << uint(j*8)
		}
	}
	return c
}

func (c coord) toBytes() [32]byte {
	var b [32]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			b[i*8+j] = byte(c[i] >> uint(j*8))
		}
	}
	return b
}

func (c coord) toHex() string {
	var hexstring = "0123456789abcdef"

	i := len(c) - 1
	for i > 0 && c[i] == 0 {
		i--
	}

	s := make([]byte, 0, 20)
	s = append(s, "0x"...)

	first := true
	for i >= 0 {
		if !first || c[i]&0xFFFFFFFF00000000 != 0 {
			for sh := 0; sh < 8; sh++ {
				ind := c[i]>>uint(60-4*sh)&0xF
				s = append(s, hexstring[ind])
			}
			s = append(s, '_')
		}
		first = false
		for sh := 0; sh < 8; sh++ {
			ind := c[i]>>uint(28-4*sh)&0xF
			s = append(s, hexstring[ind])
		}
		s = append(s, '_')
		i--
	}
	return string(s[:len(s)-1])
}

func (c *coord) copy() coord {
	c2 := coord{}
	copy(c2[:], c[:])
	return c2
}

func (c coord) reduce() coord {
	discard := coord{}
	// negative -> positive, not time safe
	for c[len(c)-1] & 8000000000000000 != 0 {
		c = c.add(coordModulus)
	}
	window := len(c)*64-256
	mod := coordModulus.rotl(uint(window))
	for i := 0; i < window+1; i++ {
		x := c.sub(mod)
		if c.compare(mod) >= 0 {
			copy(c[:], x[:])
		} else {
			copy(discard[:], x[:])
		}
		mod = mod.rotr(1)
	}
	return c
}

func (a *coord) add(b coord) coord {
	var c coord
	var carry uint64
	for i := range a {
		c[i] = a[i] + b[i] + carry
		x1 := a[i] == 0xFFFFFFFFFFFFFFFF && (carry != 0)
		x2 := b[i] == 0xFFFFFFFFFFFFFFFF && (carry != 0)
		x3 := a[i] > c[i]
		x4 := b[i] > c[i]
		carry = 0
		if x1 { carry = 1 }
		if x2 { carry = 1 }
		if x3 { carry = 1 }
		if x4 { carry = 1 }
	}
	return c
}

func (a *coord) sub(b coord) coord {
	var c coord
	var carry uint64
	for i := range a {
		c[i] = a[i] - b[i] - carry
		x1 := b[i] > a[i]
		x2 := b[i] == 0xFFFFFFFFFFFFFFFF && (carry != 0)
		x3 := b[i]+carry > a[i]
		carry = 0
		if x1 { carry = 1 }
		if x2 { carry = 1 }
		if x3 { carry = 1 }
	}
	return c
}

func (a *coord) compare(b coord) int {
	for i := len(a) - 1; i >= 0; i-- {
		if a[i] != b[i] {
			if a[i] > b[i] {
				return +1
			} else {
				return -1
			}
		}
	}
	return 0
}

func (c coord) rotl(num uint) coord {
	for num >= 64 {
		for i := len(c) - 1; i > 0; i-- {
			c[i] = c[i-1]
		}
		c[0] = 0
		num -= 64
	}

	carry := uint64(0)
	for i := 0; i < len(c)-1; i++ {
		newcarry := c[i] >> (64 - num)
		c[i] <<= num
		c[i] |= carry
		carry = newcarry
	}
	return c
}

func (c coord) rotr(num uint) coord {
	for num >= 64 {
		for i := 0; i < len(c)-2; i++ {
			c[i] = c[i+1]
		}
		c[len(c)-1] = 0
		num -= 64
	}

	carry := uint64(0)
	for i := len(c) - 1; i >= 0; i-- {
		newcarry := c[i] << (64 - num)
		c[i] >>= num
		c[i] |= carry
		carry = newcarry
	}
	return c
}

func (a coord) mult(b coord) coord {
	var sum coord
	for n := 0; n < len(a)*64; n++ {
		x := sum.add(b)
		if a[0]&1 == 1 {
			sum = x
		} else {
			_ = x
		}
		a = a.rotr(1)
		b = b.rotl(1)
	}
	return sum
}

func (a coord) nbit(t uint) int {
	i := 0
	for t >= 64 {
		i++
		t -= 64
	}
	return int(a[i] >> t & 1)
}

func (base coord) exp(exponent coord) coord {
	// from https://en.wikipedia.org/wiki/Modular_exponentiation#Right-to-left_binary_method

	result := newCoord(1)
	zero := newCoord(0)
	base = base.reduce()
	for exponent.compare(zero) > 0 {
		if exponent[0]&1 != 0 {
			result = result.mult(base).reduce()
		}
		exponent = exponent.rotr(1)
		base = base.mult(base).reduce()
	}
	
	return result
}
