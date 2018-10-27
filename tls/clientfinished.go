package tls

func makeClientFinished(conn *TLSConn) ([]byte, error) {
	finished := computeClientFinished(conn)

	hs := make([]byte, 0)
	hs = append(hs, kHS_TYPE_FINISHED)
	hs = appendLen24(hs, len(finished))
	hs = append(hs, finished...)
	hs = append(hs, kREC_TYPE_HANDSHAKE)

	return conn.createEncryptedRecord(hs)
}
