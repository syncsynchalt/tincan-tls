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
func generateTestRecords() map[string][]byte {
	records := make(map[string][]byte)
	records["client_hello"] = hexBytes(`01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba
         1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02
         4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00
         09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12
         00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00
         00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d
         8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af
         2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02
         03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02
         02 02 00 2d 00 02 01 01 00 1c 00 02 40 01`)
	records["server_hello"] = hexBytes(`02 00 00 56 03 03 a6 af 06 a4 12 18 60
         dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
         d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88
         76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1
         dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04`)
	records["server_encrypted_extensions"] = hexBytes(`08 00 00 24 00 22 00 0a 00 14 00
         12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c
         00 02 40 01 00 00 00 00`)
	records["server_certificate"] = hexBytes(`0b 00 01 b9 00 00 01 b5 00 01 b0 30 82
         01 ac 30 82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48
         86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03
         72 73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17
         0d 32 36 30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06
         03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7
         0d 01 01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f
         82 79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26
         d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c
         1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52
         4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74
         80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93
         ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03
         01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06
         03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01
         01 0b 05 00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a
         72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea
         e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01
         51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be
         c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b
         1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8
         96 12 29 ac 91 87 b4 2b 4d e1 00 00`)
	records["server_certificate_verify"] = hexBytes(`0f 00 00 84 08 04 00 80 5a 74 7c
         5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a
         b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07
         86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b
         be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44
         5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a
         3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3`)
	records["server_finished"] = hexBytes(`14 00 00 20 9b 9b 14 1d 90 63 37 fb d2 cb
         dc e7 1d f4 de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07 18`)
	records["client_finished"] = hexBytes(`14 00 00 20 a8 ec 43 6d 67 76 34 ae 52 5a
         c1 fc eb e1 1a 03 9e c1 76 94 fa c6 e9 85 27 b6 42 f2 ed d5 ce 61`)
	return records
}

// https://tools.ietf.org/html/draft-ietf-tls-tls13-vectors-07
func TestHandshakeKeys(t *testing.T) {
	conn := &TLSConn{}
	recs := generateTestRecords()
	conn.addToTranscript(recs["client_hello"])
	conn.addToTranscript(recs["server_hello"])

	clientPriv := hexBytes(`49 af 42 ba 7f 79 94 85 2d 71 3e f2 78
         4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05`)
	serverPub := hexBytes(`c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6
         72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f`)
	copy(conn.clientPrivKey[:], clientPriv)
	copy(conn.serverPubKey[:], serverPub)

	computeHandshakeKeys(conn)

	expectClient := hexBytes(`b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e
         2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21`)
	equals(t, expectClient, conn.clientHandshakeTrafficSecret[:])

	expectServer := hexBytes(`b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d
         37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38`)
	equals(t, expectServer, conn.serverHandshakeTrafficSecret[:])

	expectMaster := hexBytes(`18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a
         47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19`)
	equals(t, expectMaster, conn.masterSecret[:])

	expectCHKey := hexBytes(`db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01`)
	expectCHIV := hexBytes(`5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f`)
	equals(t, expectCHKey, conn.clientWriteKey[:])
	equals(t, expectCHIV, conn.clientWriteIV[:])
	expectSHKey := hexBytes(`3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc`)
	expectSHIV := hexBytes(`5d 31 3e b2 67 12 76 ee 13 00 0b 30`)
	equals(t, expectSHKey, conn.serverWriteKey[:])
	equals(t, expectSHIV, conn.serverWriteIV[:])
}

// https://tools.ietf.org/html/draft-ietf-tls-tls13-vectors-07
func TestServerApplicationKeys(t *testing.T) {
	conn := &TLSConn{}
	recs := generateTestRecords()
	conn.addToTranscript(recs["client_hello"])
	conn.addToTranscript(recs["server_hello"])

	clientPriv := hexBytes(`49 af 42 ba 7f 79 94 85 2d 71 3e f2 78
         4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05`)
	serverPub := hexBytes(`c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6
         72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f`)
	copy(conn.clientPrivKey[:], clientPriv)
	copy(conn.serverPubKey[:], serverPub)

	computeHandshakeKeys(conn)

	conn.addToTranscript(recs["server_encrypted_extensions"])
	conn.addToTranscript(recs["server_certificate"])
	conn.addToTranscript(recs["server_certificate_verify"])
	conn.addToTranscript(recs["server_finished"])

	computeServerApplicationKeys(conn)

	expectClientAppSecret := hexBytes(`9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce
         65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5`)
	expectServerAppSecret := hexBytes(`a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9
         50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43`)
	equals(t, expectClientAppSecret, conn.clientApplicationTrafficSecret[:])
	equals(t, expectServerAppSecret, conn.serverApplicationTrafficSecret[:])
	expectServerWriteKey := hexBytes(`9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac 92 e3 56`)
	expectServerWriteIV := hexBytes(`cf 78 2b 88 dd 83 54 9a ad f1 e9 84`)
	equals(t, expectServerWriteKey, conn.serverWriteKey[:])
	equals(t, expectServerWriteIV, conn.serverWriteIV[:])
	expectClientWriteKey := hexBytes(`db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01`)
	expectClientWriteIV := hexBytes(`5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f`)
	equals(t, expectClientWriteKey, conn.clientWriteKey[:])
	equals(t, expectClientWriteIV, conn.clientWriteIV[:])
}

func TestIllustratedHSKeys(t *testing.T) {
	conn := &TLSConn{}
	clientHello := hexBytes(`010000c20303000102030405060708090a0b0c0d0e0f101112
131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeef
f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff0006130113021303010000730000
001800160000136578616d706c652e756c666865696d2e6e6574000a0004
0002001d000d001400120403080404010503080505010806060102010033
00260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e
3b75e965d0d2cd166254002d00020101002b0003020304`)
	serverHello := hexBytes(`020000760303707172737475767778797a7b7c7d7e7f808182
838485868788898a8b8c8d8e8f20e0e1e2e3e4e5e6e7e8e9eaebecedeeef
f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff130100002e00330024001d00209f
d7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b6
15002b00020304`)
	conn.addToTranscript(clientHello)
	conn.addToTranscript(serverHello)

	clientPriv := hexBytes(`202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f`)
	serverPub := hexBytes(`9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615`)
	copy(conn.clientPrivKey[:], clientPriv)
	copy(conn.serverPubKey[:], serverPub)

	computeHandshakeKeys(conn)

	expectClient := hexBytes(`66afa331b2e837d9ee285c12047b0a80a757f917ddbfa873e1abc579da297401`)
	equals(t, expectClient, conn.clientHandshakeTrafficSecret[:])

	expectServer := hexBytes(`a56045661f3bfed8ff504c40d0c49a6cb82aebfa185eb7f52f2a915b5a292754`)
	equals(t, expectServer, conn.serverHandshakeTrafficSecret[:])

	expectMaster := hexBytes(`7f2882bb9b9a46265941653e9c2f19067118151e21d12e57a7b6aca1f8150c8d`)
	equals(t, expectMaster, conn.masterSecret[:])

	expectCHKey := hexBytes(`bd75f8a10bf81727cba7b7930f2d2d08`)
	expectCHIV := hexBytes(`80852b60fb8bf887aa6a22d1`)
	equals(t, expectCHKey, conn.clientWriteKey[:])
	equals(t, expectCHIV, conn.clientWriteIV[:])
	expectSHKey := hexBytes(`b567abf4246f473edad4efd363c5c8ad`)
	expectSHIV := hexBytes(`99dc72e32ed29ca25ffe44a5`)
	equals(t, expectSHKey, conn.serverWriteKey[:])
	equals(t, expectSHIV, conn.serverWriteIV[:])
}
