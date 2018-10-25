package tls

import (
	"encoding/hex"
	"github.com/syncsynchalt/tincan-tls/algo/hkdf"
	"github.com/syncsynchalt/tincan-tls/algo/sha256"
	"testing"
)

func TestHkdfExpandLabel(t *testing.T) {
	s := sha256.New()
	secret := hkdf.Extract(s, []byte{}, []byte{1})
	label := "label"
	context := []byte("context")
	expect, _ := hex.DecodeString("0d2bb3f622e426b79370b4c7d6de641fe0a63ae2657d006357dcf35a8796f2ff")
	keys := hkdfExpandLabel(secret, label, context, 32)
	equals(t, expect, keys)
}

// https://tools.ietf.org/html/draft-ietf-tls-tls13-vectors-07
func TestKeyDerivation(t *testing.T) {
	conn := &TLSConn{}
	clientHello := hexBytes(`
         01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba
         1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02
         4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00
         09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12
         00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00
         00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d
         8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af
         2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02
         03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02
         02 02 00 2d 00 02 01 01 00 1c 00 02 40 01`)
	serverHello := hexBytes(`
         02 00 00 56 03 03 a6 af 06 a4 12 18 60
         dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
         d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88
         76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1
         dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04`)
	conn.transcript = append(conn.transcript, clientHello...)
	conn.transcript = append(conn.transcript, serverHello...)

	clientPriv := hexBytes(`49 af 42 ba 7f 79 94 85 2d 71 3e f2 78
         4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05`)
	serverPub := hexBytes(`c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6
         72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f`)
	copy(conn.clientPrivKey[:], clientPriv)
	copy(conn.serverPubKey[:], serverPub)

	computeKeysAfterServerHello(conn)

	expectClient := hexBytes(`b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e
         2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21`)
	equals(t, expectClient, conn.clientHandshakeTrafficSecret[:])

	expectServer := hexBytes(`b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d
         37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38`)
	equals(t, expectServer, conn.serverHandshakeTrafficSecret[:])

	expectSalt := hexBytes(`43 de 77 e0 c7 77 13 85 9a 94 4d b9 db 25
         90 b5 31 90 a6 5b 3e e2 e4 f1 2d d7 a0 bb 7c e2 54 b4`)
	equals(t, expectSalt, conn.computeKeysSalt[:])

	expectCHKey := hexBytes(`db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01`)
	expectCHIV := hexBytes(`5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f`)
	equals(t, expectCHKey, conn.clientWriteKey[:])
	equals(t, expectCHIV, conn.clientWriteIV[:])
	expectSHKey := hexBytes(`3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc`)
	expectSHIV := hexBytes(`5d 31 3e b2 67 12 76 ee 13 00 0b 30`)
	equals(t, expectSHKey, conn.serverWriteKey[:])
	equals(t, expectSHIV, conn.serverWriteIV[:])
}
