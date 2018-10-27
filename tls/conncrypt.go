package tls

import (
	"github.com/syncsynchalt/tincan-tls/algo/aes"
	"github.com/syncsynchalt/tincan-tls/algo/gcm"
)

func (conn *TLSConn) decryptRecord(rechdr []byte, record []byte) (plaintext []byte) {
	cipher := aes.New128(conn.serverWriteKey[:])
	ciphertext := record[:len(record)-gcm.TagLength]
	iv := buildIV(conn.serverSeq, conn.serverWriteIV[:])
	adata := rechdr
	tag := record[len(record)-gcm.TagLength:]

	plain, failed := gcm.Decrypt(cipher, iv, ciphertext, adata, tag)
	if failed {
		panic("decrypt app record failed")
	}
	return plain
}

func (conn *TLSConn) createEncryptedRecord(plaintext []byte) ([]byte, error) {
	ll := len(plaintext) + gcm.TagLength
	iv := buildIV(conn.clientSeq, conn.clientWriteIV[:])

	rechdr := make([]byte, 0)
	rechdr = append(rechdr, kREC_TYPE_APPLICATION_DATA)
	rechdr = append(rechdr, kTLS_VERSION_12...)
	rechdr = appendLen16(rechdr, ll)

	cipher := aes.New128(conn.clientWriteKey[:])
	crypted, tag := gcm.Encrypt(cipher, iv, plaintext, rechdr)
	if ll != len(crypted)+len(tag) {
		panic("bad encrypt length calc")
	}

	rec := make([]byte, 0)
	rec = append(rec, rechdr...)
	rec = append(rec, crypted...)
	rec = append(rec, tag...)
	return rec, nil
}

func buildIV(seq uint64, base []byte) []byte {
	result := make([]byte, len(base))
	copy(result, base)
	for i := 0; i < 8; i++ {
		result[len(result)-i-1] ^= byte(seq >> uint(8*i))
	}
	return result
}
