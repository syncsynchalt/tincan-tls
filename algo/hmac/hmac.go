// This is a toy implementation and is full of side channels and other defects.
// DO NOT use this in a real cryptographic application.

// from RFC 2104

package hmac

type Hasher interface {
	Reset()
	Add([]byte)
	Sum() []byte
	BlockSize() int
}

func Compute(key, data []byte, h Hasher) []byte {
	for len(key) < h.BlockSize() {
		key = append(key, 0)
	}
	ipad := repeat(0x36, h.BlockSize())
	opad := repeat(0x5c, h.BlockSize())
	h.Reset()
	h.Add(xor(key, ipad))
	h.Add(data)
	s1 := h.Sum()
	h.Reset()
	h.Add(xor(key, opad))
	h.Add(s1)
	return h.Sum()
}

func repeat(b byte, length int) []byte {
	r := make([]byte, length)
	for i := range r {
		r[i] = b
	}
	return r
}

func min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

func xor(a, b []byte) []byte {
	l := min(len(a), len(b))
	result := make([]byte, l)
	for i := range result {
		result[i] = a[i] ^ b[i]
	}
	return result
}
