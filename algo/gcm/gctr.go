package gcm

func gctr(ciph Cipher, icb, x []byte) []byte {
	if len(icb) != 16 {
		panic("gctr bad len")
	}
	if len(x) == 0 {
		return []byte{}
	}
	y := make([]byte, 0)
	yi := make([]byte, 16)
	n := (len(x)+15)/16
	cb := make([]byte, 16)
	encout := make([]byte, 16)
	for i := 1; i <= n; i++ {
		if i == 1 {
			copy(cb, icb)
		} else {
			inc_32(cb)
		}
		ciph.Encrypt(cb, encout)
		if i < n {
			copy(yi, x[:16])
			xor(yi, encout)
			y = append(y, yi...)
			x = x[16:]
		} else {
			copy(yi, x)
			xor(yi, encout)
			y = append(y, yi[:len(x)]...)
		}
	}
	return y
}
