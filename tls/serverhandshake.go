package tls

import (
	"github.com/syncsynchalt/tincan-tls/algo/aes"
	"github.com/syncsynchalt/tincan-tls/algo/gcm"
)

func handleHandshake(conn *TLSConn, payload []byte) action {
	acts := action_none
	if len(payload) < 4 {
		panic("short handshake")
	}
	typ := int(payload[0])
	l := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if l+4 != len(payload) {
		panic("short handshake")
	}
	payload = payload[4:]
	switch byte(typ) {
	case kHS_TYPE_SERVER_HELLO:
		acts = handleServerHello(conn, payload)
		computeKeysAfterServerHello(conn)
	default:
		panic("handshake type not handled")
	}
	return acts
}

func handleHandshakeCipherText(conn *TLSConn, hdr []byte, payload []byte) action {
	acts := action_none
	_ = decryptHandshakeCipherText(conn, hdr, payload)
	panic("done!")
	return acts
}

func decryptHandshakeCipherText(conn *TLSConn, hdr []byte, payload []byte) []byte {
	cipher := aes.New128(conn.serverWriteKey[:])
	ciphertext := payload[:len(payload)-16]
	iv := buildIV(conn.serverSeq, conn.serverWriteIV[:])
	adata := hdr
	tag := payload[len(payload)-16:]

	plain, failed := gcm.GCMDecrypt(cipher, iv, ciphertext, adata, tag)
	if failed {
		panic("decrypt failed")
	}
	return plain
}

func buildIV(seq uint64, base []byte) []byte {
	result := make([]byte, len(base))
	copy(result, base)
	for i := 0; i < 8; i++ {
		result[len(result)-i-1] ^= byte(seq >> uint(8*i))
	}
	return result
}

func readVec8(payload []byte) (vec []byte, rest []byte) {
	len := uint(payload[0])
	return payload[1 : 1+len], payload[1+len:]
}

func readVec16(payload []byte) (vec []byte, rest []byte) {
	len := uint(payload[0])<<8 | uint(payload[1])
	return payload[2 : 2+len], payload[2+len:]
}

func match(c []byte, payload []byte) bool {
	for i := range c {
		if c[i] != payload[i] {
			return false
		}
	}
	return true
}

func handleServerHello(conn *TLSConn, payload []byte) action {
	// version
	payload = payload[2:]

	// server random
	if match(kHS_HELLO_RETRY_REQUEST, payload) {
		panic("server sent HelloRetryRequest")
	}
	copy(conn.serverRandom[:], payload[:32])
	payload = payload[32:]

	// session id
	_, payload = readVec8(payload)

	// cipher suite
	if !match(kTLS_AES_128_GCM_SHA256, payload) {
		panic("wrong cipher")
	}
	payload = payload[2:]

	// compression method
	if payload[0] != 0x00 {
		panic("wrong compression method")
	}
	payload = payload[1:]

	// extensions
	exts, payload := readVec16(payload)
	for len(exts) > 0 {
		typ := int(exts[0])<<8 | int(exts[1])
		var ext []byte
		ext, exts = readVec16(exts[2:])
		switch typ {
		case kEXT_KEY_SHARE:
			parseKeyShare(conn, ext)
		case kEXT_SUPPORTED_VERSIONS:
			parseSupportedVersions(conn, ext)
		default:
			panic("unknown ext type")
		}
	}

	if len(payload) != 0 {
		panic("unexpected suffix")
	}
	return action_reset_sequence
}

func parseKeyShare(conn *TLSConn, payload []byte) {
	if !match(kEXT_SUPPORTED_GROUPS_X25519, payload) {
		panic("bad group in key share")
	}
	payload = payload[2:]
	pubkey, payload := readVec16(payload)
	if len(pubkey) != 32 || len(payload) != 0 {
		panic("bad key share length")
	}
	copy(conn.serverPubKey[:], pubkey)
}

func parseSupportedVersions(conn *TLSConn, payload []byte) {
	if !match(kTLS_VERSION_13, payload) {
		panic("bad supported version")
	}
}
