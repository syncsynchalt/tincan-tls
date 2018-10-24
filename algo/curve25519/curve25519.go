// This is a toy implementation and is full of side channels and other defects.
// DO NOT use this in a real cryptographic application.

// based on RFC 7748

package curve25519

import (
	"crypto/rand"
)

var (
	u_nine_bytes = newCoord(9).toBytes()
	u_a24        = newCoord(121665)
	u_p          = coordModulus
	u_p_minus_2  = coordModulus.sub(newCoord(2))
)

func KeyPair() (priv, pub [32]byte, err error) {
	_, err = rand.Read(priv[:])
	if err != nil {
		return
	}

	b := Mult(priv, u_nine_bytes)
	copy(pub[:], b[:])
	return
}

func Mult(scalar, base [32]byte) [32]byte {
	// clamp, from https://cr.yp.to/ecdh.html
	scalar[0] &= 248
	scalar[31] &= 127 // sign bit from RFC
	scalar[31] |= 64

	k := bytesToCoord(scalar)
	u := bytesToCoord(base)

	x_1 := u.copy()
	x_2 := newCoord(1)
	z_2 := newCoord(0)
	x_3 := u.copy()
	z_3 := newCoord(1)
	swap := 0

	// Montgomery ladder around DoubleAndAdd
	for t := 255 - 1; t >= 0; t-- {
		k_t := k.nbit(uint(t))
		swap ^= k_t
		x_2, x_3 = cswap(swap, x_2, x_3)
		z_2, z_3 = cswap(swap, z_2, z_3)
		swap = k_t

		A := x_2.add(z_2).reduce()
		AA := A.mult(A).reduce()
		B := x_2.sub(z_2).reduce()
		BB := B.mult(B).reduce()
		E := AA.sub(BB).reduce()
		C := x_3.add(z_3).reduce()
		D := x_3.sub(z_3).reduce()
		DA := D.mult(A).reduce()
		CB := C.mult(B).reduce()
		x_3 = DA.add(CB).reduce()
		x_3 = x_3.mult(x_3).reduce()
		z_3 = DA.sub(CB).reduce()
		z_3 = z_3.mult(z_3).reduce()
		z_3 = x_1.mult(z_3).reduce()
		x_2 = AA.mult(BB).reduce()
		z_2 = u_a24.mult(E).reduce()
		z_2 = AA.add(z_2).reduce()
		z_2 = E.mult(z_2).reduce()
	}

	x_2, x_3 = cswap(swap, x_2, x_3)
	z_2, z_3 = cswap(swap, z_2, z_3)
	result := z_2.exp(u_p_minus_2).reduce()
	result = x_2.mult(result).reduce()
	return result.toBytes()
}

// conditional swap, with some constant-time magic
func cswap(swap int, x_2, x_3 coord) (coord, coord) {
	mask := uint64(0)
	if swap != 0 {
		mask = 0xFFFFFFFFFFFFFFFF
	} else {
		mask = 0x00
	}
	dummy := coord{}
	for i := range dummy {
		dummy[i] = mask & (x_2[i] ^ x_3[i])
		x_2[i] = x_2[i] ^ dummy[i]
		x_3[i] = x_3[i] ^ dummy[i]
	}
	return x_2, x_3
}
