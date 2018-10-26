package tls

import (
	"crypto/rand"
	"github.com/syncsynchalt/tincan-tls/algo/curve25519"
)

func makeClientHello(conn *TLSConn, hostname string) ([]byte, error) {
	b := make([]byte, 0)

	// legacy_version
	b = append(b, "\x03\x03"...)

	// random
	_, err := rand.Read(conn.clientRandom[:])
	if err != nil {
		return nil, err
	}
	b = append(b, conn.clientRandom[:]...)

	// legacy_session_id
	b = append(b, 0x00)

	// cipher suites
	b = appendLen16(b, 2)
	b = append(b, kTLS_AES_128_GCM_SHA256...)

	// legacy_compression_methods
	b = append(b, 0x01)
	b = append(b, 0x00)

	// extensions
	exts := make([]byte, 0)

	// extension - supported versions
	exts = append(exts, to16(kEXT_SUPPORTED_VERSIONS)...)
	exts = appendLen16(exts, 3)
	exts = appendLen8(exts, 2)
	exts = append(exts, kTLS_VERSION_13...)

	// extension - supported groups
	exts = append(exts, to16(kEXT_SUPPORTED_GROUPS)...)
	exts = appendLen16(exts, 4)
	exts = appendLen16(exts, 2)
	exts = append(exts, kEXT_SUPPORTED_GROUPS_X25519...)

	// extension - key share
	priv, pub, err := curve25519.KeyPair()
	if err != nil {
		return nil, err
	}
	copy(conn.clientPrivKey[:], priv[:])
	copy(conn.clientPubKey[:], pub[:])
	exts = append(exts, to16(kEXT_KEY_SHARE)...)
	exts = appendLen16(exts, len(conn.clientPubKey)+2+2+2)
	exts = appendLen16(exts, len(conn.clientPubKey)+2+2)
	exts = append(exts, kEXT_SUPPORTED_GROUPS_X25519...)
	exts = appendLen16(exts, len(conn.clientPubKey))
	exts = append(exts, conn.clientPubKey[:]...)

	// extension - server name
	exts = append(exts, to16(kEXT_SERVER_NAME)...)
	exts = appendLen16(exts, len(hostname)+5)
	exts = appendLen16(exts, len(hostname)+3)
	exts = append(exts, kEXT_SERVER_NAME_HOST)
	exts = appendLen16(exts, len(hostname))
	exts = append(exts, hostname...)

	// extension - signature algorithms
	exts = append(exts, to16(kEXT_SIGNATURE_ALGORITHMS)...)
	exts = appendLen16(exts, 8)
	exts = appendLen16(exts, 6)
	// we're not going to check the signature anyway, so advertise all the requireds
	exts = append(exts, kTLS_RSA_PKCS1_SHA256...)
	exts = append(exts, kTLS_ECDSA_SECP256R1_SHA256...)
	exts = append(exts, kTLS_RSA_PSS_RSAE_SHA256...)

	// append extensions to our handshake
	b = appendLen16(b, len(exts))
	b = append(b, exts...)

	// wrap as handshake type: client_hello
	hs := make([]byte, 0)
	hs = append(hs, kHS_TYPE_CLIENT_HELLO)
	hs = appendLen24(hs, len(b))
	hs = append(hs, b...)

	// wrap as record type: handshake
	rec := make([]byte, 0)
	rec = append(rec, kREC_TYPE_HANDSHAKE)
	rec = append(rec, kTLS_VERSION_12...)
	rec = appendLen16(rec, len(hs))
	rec = append(rec, hs...)

	return rec, nil
}

func appendLen8(b []byte, len int) []byte {
	return append(b, byte(len))
}

func appendLen16(b []byte, len int) []byte {
	b = append(b, byte(len>>8))
	return append(b, byte(len))
}

func appendLen24(b []byte, len int) []byte {
	b = append(b, byte(len>>16))
	b = append(b, byte(len>>8))
	return append(b, byte(len))
}

func to16(num int) []byte {
	return []byte{byte(num << 8), byte(num)}
}
