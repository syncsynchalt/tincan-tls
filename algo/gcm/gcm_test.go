package gcm

import (
	"encoding/hex"
	"testing"

	"github.com/syncsynchalt/tincan-tls/algo/aes"
)

func TestUInt64ToBEBytes(t *testing.T) {
	b := uint64ToBEBytes(0x00)
	equals(t, []byte{0, 0, 0, 0, 0, 0, 0, 0}, b)
	b = uint64ToBEBytes(0x01)
	equals(t, []byte{0, 0, 0, 0, 0, 0, 0, 1}, b)
	b = uint64ToBEBytes(0x0102030405060708)
	equals(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, b)
}

// from http://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
func TestGCMEncryptGuzziEmpty(t *testing.T) {
	key, _ := hex.DecodeString("00000000000000000000000000000000")
	iv, _ := hex.DecodeString("000000000000000000000000")
	pt, _ := hex.DecodeString("")
	ct, _ := hex.DecodeString("")
	aad, _ := hex.DecodeString("")
	tag, _ := hex.DecodeString("58e2fccefa7e3061367f1d57a4e7455a")

	cipher := aes.New128(key)
	cout, tout := Encrypt(cipher, iv, pt, aad)
	equals(t, ct, cout)
	equals(t, tag, tout)
}

// from http://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
func TestGCMEncryptGuzzi0Block(t *testing.T) {
	key, _ := hex.DecodeString("00000000000000000000000000000000")
	iv, _ := hex.DecodeString("000000000000000000000000")
	pt, _ := hex.DecodeString("00000000000000000000000000000000")
	ct, _ := hex.DecodeString("0388dace60b6a392f328c2b971b2fe78")
	aad, _ := hex.DecodeString("")
	tag, _ := hex.DecodeString("ab6e47d42cec13bdf53a67b21257bddf")

	cipher := aes.New128(key)
	cout, tout := Encrypt(cipher, iv, pt, aad)
	equals(t, ct, cout)
	equals(t, tag, tout)
}

// from http://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
func TestGCMEncryptGuzziNoAAD(t *testing.T) {
	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308")
	iv, _ := hex.DecodeString("cafebabefacedbaddecaf888")
	pt, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a" + "86a7a9531534f7da2e4c303d8a318a72" +
		"1c3c0c95956809532fcf0e2449a6b525" + "b16aedf5aa0de657ba637b391aafd255")
	ct, _ := hex.DecodeString("42831ec2217774244b7221b784d0d49c" + "e3aa212f2c02a4e035c17e2329aca12e" +
		"21d514b25466931c7d8f6a5aac84aa05" + "1ba30b396a0aac973d58e091473f5985")
	aad, _ := hex.DecodeString("")
	tag, _ := hex.DecodeString("4d5c2af327cd64a62cf35abd2ba6fab4")

	cipher := aes.New128(key)
	cout, tout := Encrypt(cipher, iv, pt, aad)
	equals(t, ct, cout)
	equals(t, tag, tout)
}

// from http://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
func TestGCMEncryptGuzziAAD(t *testing.T) {
	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308")
	iv, _ := hex.DecodeString("cafebabefacedbaddecaf888")
	pt, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a" + "86a7a9531534f7da2e4c303d8a318a72" +
		"1c3c0c95956809532fcf0e2449a6b525" + "b16aedf5aa0de657ba637b39")
	ct, _ := hex.DecodeString("42831ec2217774244b7221b784d0d49c" + "e3aa212f2c02a4e035c17e2329aca12e" +
		"21d514b25466931c7d8f6a5aac84aa05" + "1ba30b396a0aac973d58e091")
	aad, _ := hex.DecodeString("feedfacedeadbeeffeedfacedeadbeefabaddad2")
	tag, _ := hex.DecodeString("5bc94fbc3221a5db94fae95ae7121a47")

	cipher := aes.New128(key)
	cout, tout := Encrypt(cipher, iv, pt, aad)
	equals(t, ct, cout)
	equals(t, tag, tout)
}

// from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes
func TestGCMEncryptNISTEmpty(t *testing.T) {
	key, _ := hex.DecodeString("11754cd72aec309bf52f7687212e8957")
	iv, _ := hex.DecodeString("3c819d9a9bed087615030b65")
	pt, _ := hex.DecodeString("")
	ct, _ := hex.DecodeString("")
	aad, _ := hex.DecodeString("")
	tag, _ := hex.DecodeString("250327c674aaf477aef2675748cf6971")

	cipher := aes.New128(key)
	cout, tout := Encrypt(cipher, iv, pt, aad)
	equals(t, ct, cout)
	equals(t, tag, tout)
}

// from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes
func TestGCMEncryptNISTAADOnly(t *testing.T) {
	key, _ := hex.DecodeString("77be63708971c4e240d1cb79e8d77feb")
	iv, _ := hex.DecodeString("e0e00f19fed7ba0136a797f3")
	pt, _ := hex.DecodeString("")
	ct, _ := hex.DecodeString("")
	aad, _ := hex.DecodeString("7a43ec1d9c0a5a78a0b16533a6213cab")
	tag, _ := hex.DecodeString("209fcc8d3675ed938e9c7166709dd946")

	cipher := aes.New128(key)
	cout, tout := Encrypt(cipher, iv, pt, aad)
	equals(t, ct, cout)
	equals(t, tag, tout)
}

// from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes
func TestGCMEncryptPOnly(t *testing.T) {
	key, _ := hex.DecodeString("f00fdd018c02e03576008b516ea971ad")
	iv, _ := hex.DecodeString("3b3e276f9e98b1ecb7ce6d28")
	pt, _ := hex.DecodeString("2853e66b7b1b3e1fa3d1f37279ac82be")
	ct, _ := hex.DecodeString("55d2da7a3fb773b8a073db499e24bf62")
	aad, _ := hex.DecodeString("")
	tag, _ := hex.DecodeString("cba06bb4f6e097199250b0d19e6e4576")

	cipher := aes.New128(key)
	cout, tout := Encrypt(cipher, iv, pt, aad)
	equals(t, ct, cout)
	equals(t, tag, tout)
}

// from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes
func TestGCMEncryptBigBoth(t *testing.T) {
	key, _ := hex.DecodeString("3bb66ab4c77c70c399d4988cf1130606")
	iv, _ := hex.DecodeString("fd5fe227d3d1bff3d1b23b76")
	pt, _ := hex.DecodeString("6b63c187ff5e0fa0ffffc6493b5de747")
	ct, _ := hex.DecodeString("0a41ac0d07f1e2064950701995dea905")
	aad, _ := hex.DecodeString("6b84fa6489858a474d4196959193d115adc4bf255077412" +
		"abb6ec8bf7449bcc0365ca092ddfa287a3b747a2ab9e17138")
	tag, _ := hex.DecodeString("20d2cd594bad3a31df8f2d75f481cad0")

	cipher := aes.New128(key)
	cout, tout := Encrypt(cipher, iv, pt, aad)
	equals(t, ct, cout)
	equals(t, tag, tout)
}

// from http://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
func TestGCMDecryptGuzziEmpty(t *testing.T) {
	key, _ := hex.DecodeString("00000000000000000000000000000000")
	iv, _ := hex.DecodeString("000000000000000000000000")
	pt, _ := hex.DecodeString("")
	ct, _ := hex.DecodeString("")
	aad, _ := hex.DecodeString("")
	tag, _ := hex.DecodeString("58e2fccefa7e3061367f1d57a4e7455a")

	cipher := aes.New128(key)
	dout, failed := Decrypt(cipher, iv, ct, aad, tag)
	equals(t, false, failed)
	equals(t, pt, dout)
}

// from http://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
func TestGCMDecryptGuzzi0Block(t *testing.T) {
	key, _ := hex.DecodeString("00000000000000000000000000000000")
	iv, _ := hex.DecodeString("000000000000000000000000")
	pt, _ := hex.DecodeString("00000000000000000000000000000000")
	ct, _ := hex.DecodeString("0388dace60b6a392f328c2b971b2fe78")
	aad, _ := hex.DecodeString("")
	tag, _ := hex.DecodeString("ab6e47d42cec13bdf53a67b21257bddf")

	cipher := aes.New128(key)
	dout, failed := Decrypt(cipher, iv, ct, aad, tag)
	equals(t, false, failed)
	equals(t, pt, dout)
}

// from http://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
func TestGCMDecryptGuzziNoAAD(t *testing.T) {
	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308")
	iv, _ := hex.DecodeString("cafebabefacedbaddecaf888")
	pt, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a" + "86a7a9531534f7da2e4c303d8a318a72" +
		"1c3c0c95956809532fcf0e2449a6b525" + "b16aedf5aa0de657ba637b391aafd255")
	ct, _ := hex.DecodeString("42831ec2217774244b7221b784d0d49c" + "e3aa212f2c02a4e035c17e2329aca12e" +
		"21d514b25466931c7d8f6a5aac84aa05" + "1ba30b396a0aac973d58e091473f5985")
	aad, _ := hex.DecodeString("")
	tag, _ := hex.DecodeString("4d5c2af327cd64a62cf35abd2ba6fab4")

	cipher := aes.New128(key)
	dout, failed := Decrypt(cipher, iv, ct, aad, tag)
	equals(t, false, failed)
	equals(t, pt, dout)
}

// from http://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
func TestGCMDecryptGuzziAAD(t *testing.T) {
	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308")
	iv, _ := hex.DecodeString("cafebabefacedbaddecaf888")
	pt, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a" + "86a7a9531534f7da2e4c303d8a318a72" +
		"1c3c0c95956809532fcf0e2449a6b525" + "b16aedf5aa0de657ba637b39")
	ct, _ := hex.DecodeString("42831ec2217774244b7221b784d0d49c" + "e3aa212f2c02a4e035c17e2329aca12e" +
		"21d514b25466931c7d8f6a5aac84aa05" + "1ba30b396a0aac973d58e091")
	aad, _ := hex.DecodeString("feedfacedeadbeeffeedfacedeadbeefabaddad2")
	tag, _ := hex.DecodeString("5bc94fbc3221a5db94fae95ae7121a47")

	cipher := aes.New128(key)
	dout, failed := Decrypt(cipher, iv, ct, aad, tag)
	equals(t, false, failed)
	equals(t, pt, dout)
}

// from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes
func TestGCMDecryptNISTEmpty(t *testing.T) {
	key, _ := hex.DecodeString("11754cd72aec309bf52f7687212e8957")
	iv, _ := hex.DecodeString("3c819d9a9bed087615030b65")
	pt, _ := hex.DecodeString("")
	ct, _ := hex.DecodeString("")
	aad, _ := hex.DecodeString("")
	tag, _ := hex.DecodeString("250327c674aaf477aef2675748cf6971")

	cipher := aes.New128(key)
	dout, failed := Decrypt(cipher, iv, ct, aad, tag)
	equals(t, false, failed)
	equals(t, pt, dout)
}

// from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes
func TestGCMDecryptNISTAADOnly(t *testing.T) {
	key, _ := hex.DecodeString("77be63708971c4e240d1cb79e8d77feb")
	iv, _ := hex.DecodeString("e0e00f19fed7ba0136a797f3")
	pt, _ := hex.DecodeString("")
	ct, _ := hex.DecodeString("")
	aad, _ := hex.DecodeString("7a43ec1d9c0a5a78a0b16533a6213cab")
	tag, _ := hex.DecodeString("209fcc8d3675ed938e9c7166709dd946")

	cipher := aes.New128(key)
	dout, failed := Decrypt(cipher, iv, ct, aad, tag)
	equals(t, false, failed)
	equals(t, pt, dout)
}

// from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes
func TestGCMDecryptPOnly(t *testing.T) {
	key, _ := hex.DecodeString("f00fdd018c02e03576008b516ea971ad")
	iv, _ := hex.DecodeString("3b3e276f9e98b1ecb7ce6d28")
	pt, _ := hex.DecodeString("2853e66b7b1b3e1fa3d1f37279ac82be")
	ct, _ := hex.DecodeString("55d2da7a3fb773b8a073db499e24bf62")
	aad, _ := hex.DecodeString("")
	tag, _ := hex.DecodeString("cba06bb4f6e097199250b0d19e6e4576")

	cipher := aes.New128(key)
	dout, failed := Decrypt(cipher, iv, ct, aad, tag)
	equals(t, false, failed)
	equals(t, pt, dout)
}

// from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes
func TestGCMDecryptBigBoth(t *testing.T) {
	key, _ := hex.DecodeString("3bb66ab4c77c70c399d4988cf1130606")
	iv, _ := hex.DecodeString("fd5fe227d3d1bff3d1b23b76")
	pt, _ := hex.DecodeString("6b63c187ff5e0fa0ffffc6493b5de747")
	ct, _ := hex.DecodeString("0a41ac0d07f1e2064950701995dea905")
	aad, _ := hex.DecodeString("6b84fa6489858a474d4196959193d115adc4bf255077412" +
		"abb6ec8bf7449bcc0365ca092ddfa287a3b747a2ab9e17138")
	tag, _ := hex.DecodeString("20d2cd594bad3a31df8f2d75f481cad0")

	cipher := aes.New128(key)
	dout, failed := Decrypt(cipher, iv, ct, aad, tag)
	equals(t, false, failed)
	equals(t, pt, dout)
}

func TestGCMDecryptFails(t *testing.T) {
	key, _ := hex.DecodeString("3bb66ab4c77c70c399d4988cf1130606")
	iv, _ := hex.DecodeString("fd5fe227d3d1bff3d1b23b76")
	pt, _ := hex.DecodeString("6b63c187ff5e0fa0ffffc6493b5de747")
	ct, _ := hex.DecodeString("0a41ac0d07f1e2064950701995dea905")
	aad, _ := hex.DecodeString("6b84fa6489858a474d4196959193d115adc4bf255077412" +
		"abb6ec8bf7449bcc0365ca092ddfa287a3b747a2ab9e17138")
	tag, _ := hex.DecodeString("20d2cd594bad3a31df8f2d75f481cad1")

	cipher := aes.New128(key)
	dout, failed := Decrypt(cipher, iv, ct, aad, tag)
	equals(t, true, failed)
	equals(t, []byte{}, dout)
	_ = pt
}
