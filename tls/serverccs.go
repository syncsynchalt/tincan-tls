package tls

func handleChangeCipherSpec(conn *TLSConn, payload []byte) {
	if len(payload) != 1 || payload[0] != 1 {
		panic("weird ccs")
	}
	// ignore
}
