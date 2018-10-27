package tls

func handleHandshake(conn *TLSConn, payload []byte) action {
	acts := action_none
	if len(payload) < 4 {
		panic("short handshake")
	}
	typ := int(payload[0])
	payload, rest := readVec(24, payload[1:])
	if len(rest) != 0 {
		panic("long handshake")
	}
	switch byte(typ) {
	case kHS_TYPE_SERVER_HELLO:
		acts = handleServerHello(conn, payload)
		computeHandshakeKeys(conn)
	case kHS_TYPE_ENCRYPTED_EXTENSIONS:
		acts = handleEncryptedExtensions(conn, payload)
	case kHS_TYPE_CERTIFICATE:
		acts = handleServerCertificate(conn, payload)
	case kHS_TYPE_CERTIFICATE_VERIFY:
		acts = handleServerCertificateVerify(conn, payload)
	case kHS_TYPE_FINISHED:
		acts = handleServerFinished(conn, payload)
	default:
		panic("handshake type not handled")
	}
	return acts
}

func readNum(bits int, b []byte) uint {
	x := uint(0)
	for i := 0; i < bits; i += 8 {
		x <<= 8
		x |= uint(b[i/8])
	}
	return x
}

func readVec(lenBits int, payload []byte) (vec []byte, rest []byte) {
	len := readNum(lenBits, payload)
	return payload[uint(lenBits/8) : uint(lenBits/8)+len], payload[uint(lenBits/8)+len:]
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
	_, payload = readVec(8, payload)

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
	exts, payload := readVec(16, payload)
	parseExtensions(conn, exts)

	if len(payload) != 0 {
		panic("unexpected suffix")
	}
	return action_reset_sequence
}

func parseExtensions(conn *TLSConn, exts []byte) {
	for len(exts) > 0 {
		typ := int(exts[0])<<8 | int(exts[1])
		var ext []byte
		ext, exts = readVec(16, exts[2:])
		switch typ {
		case kEXT_SUPPORTED_GROUPS:
			parseExtSupportedGroups(conn, ext)
		case kEXT_KEY_SHARE:
			parseExtKeyShare(conn, ext)
		case kEXT_SUPPORTED_VERSIONS:
			parseExtSupportedVersions(conn, ext)
		case kEXT_SERVER_NAME:
			parseExtServerName(conn, ext)
		default:
			panic("unknown ext type")
		}
	}
}

func parseExtKeyShare(conn *TLSConn, payload []byte) {
	if !match(kEXT_SUPPORTED_GROUPS_X25519, payload) {
		panic("bad group in key share")
	}
	payload = payload[2:]
	pubkey, payload := readVec(16, payload)
	if len(pubkey) != 32 || len(payload) != 0 {
		panic("bad key share length")
	}
	copy(conn.serverPubKey[:], pubkey)
}

func parseExtSupportedVersions(conn *TLSConn, payload []byte) {
	if !match(kTLS_VERSION_13, payload) {
		panic("bad supported version")
	}
}

func parseExtSupportedGroups(conn *TLSConn, payload []byte) {
	// the server advises its preferred groups, for use in subsequent connections
}

func parseExtServerName(conn *TLSConn, payload []byte) {
	// not sure why tls13.crypto.mozilla.org sends this (empty) extension
}

func handleEncryptedExtensions(conn *TLSConn, payload []byte) action {
	exts, _ := readVec(16, payload)
	parseExtensions(conn, exts)
	return action_none
}

func handleServerCertificate(conn *TLSConn, payload []byte) action {
	// x509 authentication is outside the spec of this barest-minimal connection
	return action_none
}

func handleServerCertificateVerify(conn *TLSConn, payload []byte) action {
	// x509 authentication is outside the spec of this barest-minimal connection
	return action_none
}

func handleServerFinished(conn *TLSConn, payload []byte) action {
	expectedResult := computeServerFinished(conn)
	if len(expectedResult) != len(payload) {
		panic("server finished bytes differ")
	}
	for i := range payload {
		if expectedResult[i] != payload[i] {
			panic("server finished unexpected result")
		}
	}
	computeServerApplicationKeys(conn)
	return action_send_finished | action_reset_sequence
}
