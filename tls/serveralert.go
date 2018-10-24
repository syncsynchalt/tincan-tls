package tls

func handleAlert(conn *TLSConn, payload []byte) {
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
		panic(prefix + "access_denied")
	case 50:
		panic(prefix + "decode_error")
	case 51:
		panic(prefix + "decrypt_error")
	case 70:
		panic(prefix + "protocol_version")
	case 71:
		panic(prefix + "insufficient_security")
	case 80:
		panic(prefix + "internal_error")
	case 86:
		panic(prefix + "inappropriate_fallback")
	case 90:
		panic(prefix + "user_canceled")
	case 109:
		panic(prefix + "missing_extension")
	case 110:
		panic(prefix + "unsupported_extension")
	case 112:
		panic(prefix + "unrecognized_name")
	case 113:
		panic(prefix + "bad_certificate_status_response")
	case 115:
		panic(prefix + "unknown_psk_identity")
	case 116:
		panic(prefix + "certificate_required")
	case 120:
		panic(prefix + "no_application_protocol")
	default:
		panic(prefix + "unknown alert")
	}
}
