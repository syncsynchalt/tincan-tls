package tls

import (
	"github.com/syncsynchalt/tincan-tls/algo/hmac"
	"github.com/syncsynchalt/tincan-tls/algo/sha256"
)

func computeServerFinished(conn *TLSConn) []byte {
	finishedKey := hkdfExpandLabel(conn.serverHandshakeTrafficSecret[:], "finished", []byte{}, kSHA256OutLen)
	transcriptHash := sha256.SumData(conn.lastTranscript)
	return hmac.Compute(finishedKey, transcriptHash, sha256.New())
}

func computeClientFinished(conn *TLSConn) []byte {
	finishedKey := hkdfExpandLabel(conn.clientHandshakeTrafficSecret[:], "finished", []byte{}, kSHA256OutLen)
	transcriptHash := sha256.SumData(conn.transcript)
	return hmac.Compute(finishedKey, transcriptHash, sha256.New())
}
