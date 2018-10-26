package tls

func handleChangeCipherSpec(conn *TLSConn, payload []byte) action {
	if len(payload) != 1 || payload[0] != 1 {
		panic("weird ccs")
	}
	return action_reset_sequence
}
