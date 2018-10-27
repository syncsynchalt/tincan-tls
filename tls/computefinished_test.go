package tls

import (
	"testing"
)

// https://tools.ietf.org/html/draft-ietf-tls-tls13-vectors-07
func TestComputeFinished(t *testing.T) {
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

	expected := hexBytes(`9b 9b 14 1d 90 63 37 fb d2 cb dc e7 1d f4
         de da 4a b4 2c 30 95 72 cb 7f ff ee 54 54 b7 8f 07 18`)
	calculated := computeServerFinished(conn)
	equals(t, expected, calculated)
}
