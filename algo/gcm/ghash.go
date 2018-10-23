package gcm

func ghash(H, X []byte) []byte {
	if len(H) != 16 || len(X) % 16 != 0 {
		panic("ghash bad length")
	}
	Y := make([]byte, 16)
	for len(X) > 0 {
		xor(Y, X[:16])
		Y = multBlocks(Y, H)
		X = X[16:]
	}
	return Y
}
