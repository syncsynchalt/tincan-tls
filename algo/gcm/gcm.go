// This is a toy implementation and is full of side channels and other defects.
// DO NOT use this in a real cryptographic application.

// based on NIST SP 800-38D (https://csrc.nist.gov/publications/detail/sp/800-38d/final)

package gcm

var (
	// from RFC 5288, all defined AEAD ciphers have tag length of 128 bits
	taglength = 16
)

type Cipher interface {
	BlockSize() int
	KeySize() int
	Encrypt(in, out []byte)
}

func GCMEncrypt(cipher Cipher, iv, plaintext, adata []byte) (ciphertext []byte, authtag []byte) {
	if len(iv) != 12 {
		panic("gcm unexpected iv length")
	}

	zeroBlock := make([]byte, cipher.BlockSize())
	H := make([]byte, cipher.BlockSize())
	cipher.Encrypt(zeroBlock, H)

	J0 := append(iv, 0, 0, 0, 1)
	J1 := copyBytes(J0); inc_32(J1)

	ctext := gctr(cipher, J1, plaintext)
	u := (16 - len(ctext)%16) % 16
	v := (16 - len(adata)%16) % 16

	inS := adata
	inS = append(inS, zeroBlock[:v]...)
	inS = append(inS, ctext...)
	inS = append(inS, zeroBlock[:u]...)
	inS = append(inS, uint64ToBEBytes(uint64(8*len(adata)))...)
	inS = append(inS, uint64ToBEBytes(uint64(8*len(ctext)))...)
	S := ghash(H, inS)

	T := gctr(cipher, J0, S)
	T = T[:taglength]

	return ctext, T
}

func uint64ToBEBytes(n uint64) []byte {
	b := make([]byte, 8)
	for i := 0; i < 8; i++ {
		b[i] = byte(n>>uint(56-8*i))
	}
	return b
}

func copyBytes(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

func GCMDecrypt(cipher Cipher, iv, ciphertext, adata, tag []byte) (plaintext []byte, failed bool) {
	if len(iv) != 12 {
		panic("gcm unexpected iv length")
	}

	zeroBlock := make([]byte, cipher.BlockSize())
	H := make([]byte, cipher.BlockSize())
	cipher.Encrypt(zeroBlock, H)

	J0 := append(iv, 0, 0, 0, 1)
	J1 := copyBytes(J0); inc_32(J1)

	plain := gctr(cipher, J1, ciphertext)
	u := (16 - len(ciphertext)%16) % 16
	v := (16 - len(adata)%16) % 16

	inS := adata
	inS = append(inS, zeroBlock[:v]...)
	inS = append(inS, ciphertext...)
	inS = append(inS, zeroBlock[:u]...)
	inS = append(inS, uint64ToBEBytes(uint64(8*len(adata)))...)
	inS = append(inS, uint64ToBEBytes(uint64(8*len(ciphertext)))...)
	S := ghash(H, inS)

	T := gctr(cipher, J0, S)
	T = T[:taglength]
	for i := range tag {
		if T[i] != tag[i] {
			return []byte{}, true
		}
	}
	return plain, false
}
