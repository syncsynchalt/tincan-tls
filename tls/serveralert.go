package tls

func handleAlert(conn *TLSConn, payload []byte) action {
	if len(payload) < 2 {
		panic("short alert")
	}

	prefix := ""
	switch payload[0] {
	case 1:
		prefix = "warning alert: "
	case 2:
		prefix = "fatal alert: "
	default:
		prefix = "unknown alert: "
	}

	switch payload[1] {
	case 0:
		panic(prefix + "close notify")
	case 10:
		panic(prefix + "unexpected message")
	case 20:
		panic(prefix + "bad record MAC")
	case 22:
		panic(prefix + "record overflow")
	case 40:
		panic(prefix + "handshake failure")
	case 42:
		panic(prefix + "bad certificate")
	case 43:
		panic(prefix + "unsupported certificate")
	case 44:
		panic(prefix + "certificate revoked")
	case 45:
		panic(prefix + "certificate expired")
	case 46:
		panic(prefix + "certificate unknown")
	case 47:
		panic(prefix + "illegal parameter")
	case 48:
		panic(prefix + "unknown CA")
	case 49:
		panic(prefix + "access denied")
	case 50:
		panic(prefix + "decode error")
	case 51:
		panic(prefix + "decrypt error")
	case 70:
		panic(prefix + "protocol version")
	case 71:
		panic(prefix + "insufficient security")
	case 80:
		panic(prefix + "internal error")
	case 86:
		panic(prefix + "inappropriate fallback")
	case 90:
		panic(prefix + "user canceled")
	case 109:
		panic(prefix + "missing extension")
	case 110:
		panic(prefix + "unsupported extension")
	case 112:
		panic(prefix + "unrecognized name")
	case 113:
		panic(prefix + "bad certificate status response")
	case 115:
		panic(prefix + "unknown PSK identity")
	case 116:
		panic(prefix + "certificate required")
	case 120:
		panic(prefix + "no application protocol")
	default:
		panic(prefix + "unknown alert")
	}
}
