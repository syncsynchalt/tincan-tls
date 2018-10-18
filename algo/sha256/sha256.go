// This is a toy implementation and is full of side channels and other defects.
// DO NOT use this in a real cryptographic application.

// based on RFC 6234

package sha256

var k = [...]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}
var initialState = [...]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

type Sha256 struct {
	tmp            [64]byte
	unprocessed    [64]byte
	unprocessedLen int
	state          [8]uint32
	addBits        uint64
}

func New() *Sha256 {
	return &Sha256{state: initialState}
}

func (s *Sha256) Add(in []byte) {
	s.addBits += uint64(8 * len(in))
	var b []byte
	for len(in)+s.unprocessedLen >= 64 {
		if s.unprocessedLen == 0 {
			b = in[:64]
			in = in[64:]
		} else {
			copy(s.tmp[:], s.unprocessed[:s.unprocessedLen])
			copy(s.tmp[s.unprocessedLen:], in)
			b = s.tmp[:]
			in = in[64-s.unprocessedLen:]
			s.unprocessedLen = 0
		}

		s.chomp(b)
	}
	if len(in) > 0 {
		copy(s.unprocessed[s.unprocessedLen:], in)
		s.unprocessedLen += len(in)
	}
}

func (s *Sha256) chomp(block []byte) {
	var w [64]uint32
	for t := 0; t < 16; t++ {
		w[t] = uint32(
			uint32(block[t*4+0])<<24 |
				uint32(block[t*4+1])<<16 |
				uint32(block[t*4+2])<<8 |
				uint32(block[t*4+3])<<0)
	}
	for t := 16; t < 64; t++ {
		w[t] = ssig1(w[t-2]) + w[t-7] + ssig0(w[t-15]) + w[t-16]
	}

	a, b, c, d, e, f, g, h := s.state[0], s.state[1], s.state[2], s.state[3],
		s.state[4], s.state[5], s.state[6], s.state[7]
	var t1, t2 uint32

	for i := 0; i < 64; i++ {
		t1 = h + bsig1(e) + ch(e, f, g) + k[i] + w[i]
		t2 = bsig0(a) + maj(a, b, c)
		h = g
		g = f
		f = e
		e = d + t1
		d = c
		c = b
		b = a
		a = t1 + t2
	}
	s.state[0] = a + s.state[0]
	s.state[1] = b + s.state[1]
	s.state[2] = c + s.state[2]
	s.state[3] = d + s.state[3]
	s.state[4] = e + s.state[4]
	s.state[5] = f + s.state[5]
	s.state[6] = g + s.state[6]
	s.state[7] = h + s.state[7]
}

func ch(x, y, z uint32) uint32 {
	return (x & y) ^ (^x & z)
}

func maj(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}

func rotr(x uint32, n uint) uint32 {
	return (x >> n) | (x << (32 - n))
}

func rotl(x uint32, n uint) uint32 {
	return (x << n) | (x >> (32 - n))
}

func bsig0(x uint32) uint32 {
	return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

func bsig1(x uint32) uint32 {
	return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

func ssig0(x uint32) uint32 {
	return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

func ssig1(x uint32) uint32 {
	return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

func (s *Sha256) finalPad() {
	// assumes we'll never max out L to reach these bits, so we consume the whole byte
	s.unprocessed[s.unprocessedLen] = 0x80
	s.unprocessedLen++
	for s.unprocessedLen > 56 && s.unprocessedLen < 64 {
		s.unprocessed[s.unprocessedLen] = 0
		s.unprocessedLen++
	}
	if s.unprocessedLen >= 64 {
		s.chomp(s.unprocessed[:])
	}
	for s.unprocessedLen < 56 {
		s.unprocessed[s.unprocessedLen] = 0
		s.unprocessedLen++
	}
	s.unprocessed[56] = byte(s.addBits >> 56)
	s.unprocessed[57] = byte(s.addBits >> 48)
	s.unprocessed[58] = byte(s.addBits >> 40)
	s.unprocessed[59] = byte(s.addBits >> 32)
	s.unprocessed[60] = byte(s.addBits >> 24)
	s.unprocessed[61] = byte(s.addBits >> 16)
	s.unprocessed[62] = byte(s.addBits >> 8)
	s.unprocessed[63] = byte(s.addBits >> 0)
	s.chomp(s.unprocessed[:])
	s.unprocessedLen = 0
}

func (s *Sha256) Sum() (result [32]byte) {
	s.finalPad()
	for i := 0; i < 8; i++ {
		result[i*4+0] = byte(s.state[i] >> 24)
		result[i*4+1] = byte(s.state[i] >> 16)
		result[i*4+2] = byte(s.state[i] >> 8)
		result[i*4+3] = byte(s.state[i] >> 0)
	}
	return
}
