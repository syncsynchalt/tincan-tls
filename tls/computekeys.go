package tls

import (
	"github.com/syncsynchalt/tincan-tls/algo/ecdhe"
	"github.com/syncsynchalt/tincan-tls/algo/hkdf"
	"github.com/syncsynchalt/tincan-tls/algo/sha256"
)

func computeHandshakeKeys(conn *TLSConn) {
	salt := []byte{}
	psk := [32]byte{}
	sharedSecret := ecdhe.CalculateSharedSecret(conn.clientPrivKey[:], conn.serverPubKey[:])
	earlySecret := hkdf.Extract(sha256.New(), salt, psk[:])
	derivedSecret := deriveSecret(earlySecret, "derived", []byte{})
	handshakeSecret := hkdf.Extract(sha256.New(), derivedSecret, sharedSecret)
	copy(conn.clientHandshakeTrafficSecret[:], deriveSecret(handshakeSecret, "c hs traffic", conn.transcript))
	copy(conn.serverHandshakeTrafficSecret[:], deriveSecret(handshakeSecret, "s hs traffic", conn.transcript))
	derivedSecret = deriveSecret(handshakeSecret, "derived", []byte{})
	zeros := [32]byte{}
	masterSecret := hkdf.Extract(sha256.New(), derivedSecret, zeros[:])
	copy(conn.masterSecret[:], masterSecret)
	csecret := conn.clientHandshakeTrafficSecret[:]
	ssecret := conn.serverHandshakeTrafficSecret[:]
	copy(conn.clientWriteKey[:], hkdfExpandLabel(csecret, "key", []byte{}, len(conn.clientWriteKey)))
	copy(conn.serverWriteKey[:], hkdfExpandLabel(ssecret, "key", []byte{}, len(conn.serverWriteKey)))
	copy(conn.clientWriteIV[:], hkdfExpandLabel(csecret, "iv", []byte{}, len(conn.clientWriteIV)))
	copy(conn.serverWriteIV[:], hkdfExpandLabel(ssecret, "iv", []byte{}, len(conn.serverWriteIV)))
	conn.serverSeq = 0
	conn.clientSeq = 0
}

func computeServerApplicationKeys(conn *TLSConn) {
	copy(conn.serverApplicationTrafficSecret[:], deriveSecret(conn.masterSecret[:], "s ap traffic", conn.transcript))
	copy(conn.clientApplicationTrafficSecret[:], deriveSecret(conn.masterSecret[:], "c ap traffic", conn.transcript))
	ssecret := conn.serverApplicationTrafficSecret[:]
	copy(conn.serverWriteKey[:], hkdfExpandLabel(ssecret, "key", []byte{}, len(conn.serverWriteKey)))
	copy(conn.serverWriteIV[:], hkdfExpandLabel(ssecret, "iv", []byte{}, len(conn.serverWriteIV)))
	conn.serverSeq = 0
}

func computeClientApplicationKeys(conn *TLSConn) {
	csecret := conn.clientApplicationTrafficSecret[:]
	copy(conn.clientWriteKey[:], hkdfExpandLabel(csecret, "key", []byte{}, len(conn.clientWriteKey)))
	copy(conn.clientWriteIV[:], hkdfExpandLabel(csecret, "iv", []byte{}, len(conn.clientWriteIV)))
	conn.clientSeq = 0
}

func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	hkdflabel := make([]byte, 0)
	hkdflabel = append(hkdflabel, byte(length>>8))
	hkdflabel = append(hkdflabel, byte(length))
	hkdflabel = append(hkdflabel, byte(len(label)+6))
	hkdflabel = append(hkdflabel, "tls13 "...)
	hkdflabel = append(hkdflabel, label...)
	hkdflabel = append(hkdflabel, byte(len(context)))
	hkdflabel = append(hkdflabel, context...)
	return hkdf.Expand(sha256.New(), secret, hkdflabel, length)
}

func deriveSecret(secret []byte, label string, messages []byte) []byte {
	s := sha256.New()
	s.Add(messages)
	sum := s.Sum()
	return hkdfExpandLabel(secret, label, sum, len(sum))
}
