package tls

import (
	"github.com/syncsynchalt/tincan-tls/algo/ecdhe"
	"github.com/syncsynchalt/tincan-tls/algo/hkdf"
	"github.com/syncsynchalt/tincan-tls/algo/sha256"
)

func computeKeysAfterServerHello(conn *TLSConn) {
	salt := []byte{}
	psk := [32]byte{}
	sharedSecret := ecdhe.CalculateSharedSecret(conn.clientPrivKey[:], conn.serverPubKey[:])
	earlySecret := hkdf.Extract(sha256.New(), salt, psk[:])
	derivedSecret := deriveSecret(earlySecret, "derived", []byte{})
	handshakeSecret := hkdf.Extract(sha256.New(), derivedSecret, sharedSecret)
	copy(conn.clientHandshakeTrafficSecret[:], deriveSecret(handshakeSecret, "c hs traffic", conn.transcript))
	copy(conn.serverHandshakeTrafficSecret[:], deriveSecret(handshakeSecret, "s hs traffic", conn.transcript))
	derivedSecret = deriveSecret(handshakeSecret, "derived", []byte{})
	copy(conn.computeKeysSalt[:], derivedSecret)
	csecret := conn.clientHandshakeTrafficSecret[:]
	ssecret := conn.serverHandshakeTrafficSecret[:]
	copy(conn.clientWriteKey[:], hkdfExpandLabel(csecret, "key", []byte{}, len(conn.clientWriteKey)))
	copy(conn.serverWriteKey[:], hkdfExpandLabel(ssecret, "key", []byte{}, len(conn.serverWriteKey)))
	copy(conn.clientWriteIV[:], hkdfExpandLabel(csecret, "iv", []byte{}, len(conn.clientWriteIV)))
	copy(conn.serverWriteIV[:], hkdfExpandLabel(ssecret, "iv", []byte{}, len(conn.serverWriteIV)))
}

// xxx put this in appropriate place
// xxx test
func computeKeysAfterServerFinished(conn *TLSConn) {
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
