package tls

import (
	"github.com/syncsynchalt/tincan-tls/algo/aes"
	"github.com/syncsynchalt/tincan-tls/algo/gcm"
)

func makeClientFinished(conn *TLSConn) ([]byte, error) {
	finished := computeClientFinished(conn)

	hs := make([]byte, 0)
	hs = append(hs, kHS_TYPE_FINISHED)
	hs = appendLen24(hs, len(finished))
	hs = append(hs, finished...)
	hs = append(hs, kREC_TYPE_HANDSHAKE)

	ll := len(hs) + gcm.TagLength

	iv := buildIV(conn.clientSeq, conn.clientWriteIV[:])

	rechdr := make([]byte, 0)
	rechdr = append(rechdr, kREC_TYPE_APPLICATION_DATA)
	rechdr = append(rechdr, kTLS_VERSION_12...)
	rechdr = appendLen16(rechdr, ll)

	cipher := aes.New128(conn.clientWriteKey[:])
	crypted, tag := gcm.Encrypt(cipher, iv, hs, rechdr)
	if ll != len(crypted)+len(tag) {
		panic("bad encrypt length calc")
	}

	rec := make([]byte, 0)
	rec = append(rec, rechdr...)
	rec = append(rec, crypted...)
	rec = append(rec, tag...)
	return rec, nil
}
