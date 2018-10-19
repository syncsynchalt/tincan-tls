// This is a toy implementation and is full of side channels and other defects.
// DO NOT use this in a real cryptographic application.

// based on FIPS 197 (https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)

package aes128

// aes128 values
const (
	nk = 4
	nb = 4
	nr = 10
)

var sbox [256]byte = generateSBox()

type AES struct {
	w []uint32
	out []byte
}

func New128(key []byte) *AES {
	a := AES{}
	a.w = keyExpansion(key)
	a.out = make([]byte, 4*nb)
	return &a
}

func (a *AES) BlockSize() int {
	return 4*nb
}

func (a *AES) KeySize() int {
	return 4*nk
}

func (a *AES) Cipher(in []byte) []byte {
	cipher(in, a.out, a.w)
	return a.out
}

// returns a 16x16 substitution box
func generateSBox() [256]byte {
	inverses := make([]byte, 256)
	for i := range inverses {
		inverses[i] = findInverse(byte(i))
	}
	var box [256]byte
	for i := range box {
		box[i] = sboxAffine(inverses[i])
	}
	return box
}

func findInverse(b byte) byte {
	// find the multiplicative inverse in GF(2^8) for reducing polynomial of x^8 + x^4 + x^3 + x + 1 (100011011b)
	// in other words, b * bi == 1
	// uses brute-force method to find inverses (slow)
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

	// mod x^8 + x^4 + x^3 + x + 1 (reduces result to 8 bits)
	for i := uint(15); i > 7; i-- {
		if result&(1<<i) != 0 {
			result = result ^ (0x11b << (i - 8))
		}
	}

	return byte(result)
}

func sboxAffine(b byte) byte {
	isSet := func(i uint) bool { return (b & (1 << (i % 8))) != 0 }
	affineBit := func(i uint) bool {
		c := (0x63 & (1 << i)) != 0
		return isSet(i) != isSet(i+4) != isSet(i+5) != isSet(i+6) != isSet(i+7) != c
	}
	bp := byte(0)
	for i := uint(0); i < 8; i++ {
		if affineBit(i) {
			bp |= 1 << i
		}
	}
	return bp
}

// key is 128 bits (16 bytes), result is 4*nb*(nr+1) = 176 bytes
func keyExpansion(key []byte) []uint32 {
	w := make([]uint32, nb*(nr+1))
	for i := 0; i < nk; i++ {
		w[i] = uint32(key[4*i])<<24 | uint32(key[4*i+1])<<16 | uint32(key[4*i+2])<<8 | uint32(key[4*i+3])
	}

	var rcon [nb * (nr + 1) / nk]uint32
	rcon[0] = uint32(0x01000000)
	for i := 1; i < len(rcon); i++ {
		// multiply each by 2 and reduce by modulus
		rcon[i] = uint32(rjmult(byte(rcon[i-1]>>24), 2)) << 24
	}

	var tmp uint32
	for i := nk; i < nb*(nr+1); i++ {
		tmp = w[i-1]
		if i%nk == 0 {
			tmp = subWord(rotWord(tmp)) ^ rcon[i/nk-1]
		} else if nk > 6 && i%nk == 4 {
			// not reached in AES128
			tmp = subWord(tmp)
		}
		w[i] = w[i-nk] ^ tmp
	}
	return w
}

func subWord(w uint32) uint32 {
	return uint32(sbox[byte(w>>24)])<<24 | uint32(sbox[byte(w>>16)])<<16 |
		uint32(sbox[byte(w>>8)])<<8 | uint32(sbox[byte(w)])
}

func rotWord(w uint32) uint32 {
	return (w << 8) | (w >> 24)
}

// w is the output of keyExpansion()
func cipher(in, out []byte, w []uint32) {
	if len(in) != 4*nb || len(in) != len(out) {
		panic("incorrect blocksize in cipher")
	}

	state := out

	copy(state, in)
	addRoundKey(state, w[:nb])

	for i := 1; i < nr; i++ {
		subBytes(state)
		shiftRows(state)
		mixColumns(state)
		addRoundKey(state, w[(i)*nb:(i+1)*nb])
	}

	subBytes(state)
	shiftRows(state)
	addRoundKey(state, w[nr*nb:(nr+1)*nb])
}

func subBytes(state []byte) {
	for i := range state {
		state[i] = sbox[state[i]]
	}
}

func addRoundKey(state []byte, w []uint32) {
	if len(state) != 4*len(w) {
		panic("mismatch in state and w")
	}
	for i := range w {
		state[i*4+0] ^= byte(w[i] >> 24)
		state[i*4+1] ^= byte(w[i] >> 16)
		state[i*4+2] ^= byte(w[i] >> 8)
		state[i*4+3] ^= byte(w[i])
	}
}

func shiftRows(state []byte) {
	roll := func(col int) {
		x := state[col]
		for i := 0; i < nb-1; i++ {
			state[col+4*i] = state[col+4*(i+1)]
		}
		state[col+4*(nb-1)] = x
	}
	for i := 1; i < nb; i++ {
		for j := 0; j < i; j++ {
			roll(i)
		}
	}
}

func mixColumns(state []byte) {
	mix := func(s []byte) {
		s0 := rjmult(2, s[0]) ^ rjmult(3, s[1]) ^ s[2] ^ s[3]
		s1 := s[0] ^ rjmult(2, s[1]) ^ rjmult(3, s[2]) ^ s[3]
		s2 := s[0] ^ s[1] ^ rjmult(2, s[2]) ^ rjmult(3, s[3])
		s3 := rjmult(3, s[0]) ^ s[1] ^ s[2] ^ rjmult(2, s[3])
		s[0], s[1], s[2], s[3] = s0, s1, s2, s3
	}
	mix(state[0:4])
	mix(state[4:8])
	mix(state[8:12])
	mix(state[12:16])
}
