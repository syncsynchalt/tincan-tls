// This is a toy implementation and is full of side channels and other defects.
// DO NOT use this in a real cryptographic application.

// based on FIPS 197 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)

package aes128

// returns a 16x16 substitution box
func generateSBox() []byte {
	inverses := make([]byte, 256)
	for i := 0; i < 256; i++ {
		inverses[i] = findInverse(byte(i))
	}
	box := make([]byte, 256)
	for i := 0; i < 256; i++ {
		box[i] = sboxAffine(inverses[i])
	}
	return box
}

// xxx change to lookup table
func findInverse(b byte) byte {
	// find the multiplicative inverse in GF(2^8) for reducing polynomial of x^8 + x^4 + x^3 + x + 1 (100011011b)
	// uses brute-force method (slow)
	if b == 0 {
		return 0
	}
	for i := 0; i < 256; i++ {
		if rjmult(byte(i), b) == 1 {
			return byte(i)
		}
	}
	panic("no inverse found, can't happen")
}

func rjmult(a, b byte) byte {
	result := uint(0)

	// polynomial expansion of abit_i*x^i times bbit_i*x^i
	ascale := uint(0)
	for a != 0 {
		if a&1 == 1 {
			bscale := uint(0)
			bt := b
			for bt != 0 {
				if bt&1 == 1 {
					result ^= 1 << (ascale + bscale)
				}
				bt >>= 1
				bscale++
			}
		}
		a >>= 1
		ascale++
	}

	// mod x^8 + x^4 + x^3 + x + 1 (aka reduce result)
	for i := uint(15); i > 7; i-- {
		if result&(1<<i) != 0 {
			result = result ^ (0x11b << (i - 8))
		}
	}

	return byte(result)
}

func sboxAffine(b byte) byte {
	affineBit := func(i uint) bool {
		ba := (b & (1 << i)) != 0
		bb := (b & (1 << ((i + 4) % 8))) != 0
		bc := (b & (1 << ((i + 5) % 8))) != 0
		bd := (b & (1 << ((i + 6) % 8))) != 0
		be := (b & (1 << ((i + 7) % 8))) != 0
		c := (0x63 & (1 << i)) != 0
		return ba != bb != bc != bd != be != c
	}
	bp := byte(0)
	for i := uint(0); i < 8; i++ {
		if affineBit(i) {
			bp |= 1 << i
		}
	}
	return bp
}
