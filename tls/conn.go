package tls

type Conn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

const (
	kX25519KeyLen = 32
	kSHA256OutLen = 32
	kAES128KeyLen = 16
	kGCMIVLen     = 12
)

type TLSConn struct {
	raw            Conn
	clientRandom   [32]byte
	clientPrivKey  [kX25519KeyLen]byte
	clientPubKey   [kX25519KeyLen]byte
	serverRandom   [32]byte
	serverPubKey   [kX25519KeyLen]byte
	transcript     []byte
	lastTranscript []byte
	secret0        [32]byte
	masterSecret   [kSHA256OutLen]byte
	serverSeq      uint64
	clientSeq      uint64
	clientWriteKey [kAES128KeyLen]byte
	serverWriteKey [kAES128KeyLen]byte
	clientWriteIV  [kGCMIVLen]byte
	serverWriteIV  [kGCMIVLen]byte

	clientHandshakeTrafficSecret   [kSHA256OutLen]byte
	serverHandshakeTrafficSecret   [kSHA256OutLen]byte
	clientApplicationTrafficSecret [kSHA256OutLen]byte
	serverApplicationTrafficSecret [kSHA256OutLen]byte

	readBuf  []byte
	writeBuf []byte
}

type action int

const (
	action_none           = action(0)
	action_reset_sequence = action(1 << iota)
	action_send_finished  = action(1 << iota)
)

func NewConn(raw Conn, hostname string) (Conn, error) {
	conn := &TLSConn{raw: raw}
	rec, err := makeClientHello(conn, hostname)
	if err != nil {
		panic(err)
	}
	err = writeHandshakeRecord(conn, rec)
	if err != nil {
		return nil, err
	}

	for {
		finished, err := conn.readRecord()
		if err != nil {
			panic(err)
		}
		if finished {
			break
		}
	}
	return conn, nil
}

func writeHandshakeRecord(conn *TLSConn, rec []byte) error {
	n, err := conn.raw.Write(rec)
	if err != nil {
		return err
	}
	if n != len(rec) {
		panic("short write")
	}
	conn.addToTranscript(rec[5:])
	return nil
}

func (conn *TLSConn) readRaw(b []byte) error {
	for len(b) > 0 {
		n, err := conn.raw.Read(b)
		b = b[n:]
		if err != nil {
			return err
		}
	}
	return nil
}

func (conn *TLSConn) writeRaw(b []byte) error {
	for len(b) > 0 {
		n, err := conn.raw.Write(b)
		b = b[n:]
		if err != nil {
			return err
		}
	}
	return nil
}

func (conn *TLSConn) Read(b []byte) (n int, err error) {
	if len(conn.readBuf) == 0 {
		_, err = conn.readRecord()
		if err != nil {
			return 0, err
		}
	}
	l := len(conn.readBuf)
	if l > len(b) {
		l = len(b)
	}
	copy(b[:l], conn.readBuf)
	conn.readBuf = conn.readBuf[l:]
	if len(conn.readBuf) == 0 {
		// reclaim memory
		conn.readBuf = nil
	}
	return l, nil
}

func (conn *TLSConn) readRecord() (handshakeFinished bool, err error) {
	hdrbuf := make([]byte, 5)
	err = conn.readRaw(hdrbuf)
	if err != nil {
		return false, err
	}
	typ := int(hdrbuf[0])
	length := readNum(16, hdrbuf[3:])
	payload := make([]byte, length)
	err = conn.readRaw(payload)
	if err != nil {
		return false, err
	}
	acts := conn.handleRecord(typ, hdrbuf, payload)
	conn.serverSeq++
	if acts&action_reset_sequence != 0 {
		conn.serverSeq = 0
		conn.clientSeq = 0
	}
	if acts&action_send_finished != 0 {
		rec, err := makeClientFinished(conn)
		if err != nil {
			panic(err)
		}
		err = writeHandshakeRecord(conn, rec)
		if err != nil {
			return false, err
		}
		computeClientApplicationKeys(conn)
		return true, err
	}
	return false, nil
}

func lastByte(bb []byte) (last byte, rest []byte) {
	if len(bb) == 0 {
		panic("lastbyte on empty record")
	}
	b := bb[len(bb)-1]
	return b, bb[:len(bb)-1]
}

func (conn *TLSConn) Write(b []byte) (n int, err error) {
	tosend := make([]byte, 0)
	tosend = append(tosend, b...)
	tosend = append(tosend, kREC_TYPE_APPLICATION_DATA)
	encrypted, err := conn.createEncryptedRecord(tosend)
	if err != nil {
		return 0, err
	}
	err = conn.writeRaw(encrypted)
	conn.clientSeq++
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (conn *TLSConn) Close() (err error) {
	return conn.raw.Close()
}

func (conn *TLSConn) handleRecord(typ int, rechdr []byte, payload []byte) action {
	switch byte(typ) {
	case kREC_TYPE_CHANGE_CIPHER_SPEC:
		return handleChangeCipherSpec(conn, payload)
	case kREC_TYPE_ALERT:
		return handleAlert(conn, payload)
	case kREC_TYPE_HANDSHAKE:
		conn.addToTranscript(payload)
		return handleHandshake(conn, payload)
	case kREC_TYPE_APPLICATION_DATA:
		plain := conn.decryptRecord(rechdr, payload)
		return conn.dispatchRecordContents(rechdr, plain)
	default:
		panic("unrecognized handshake-context record type")
	}
}

// parses TLSInnerPlaintext
func (conn *TLSConn) dispatchRecordContents(hdr []byte, inner []byte) action {
    for len(inner) != 0 && inner[len(inner)-1] == '\000' {
        inner = inner[:len(inner)-1]
    }
	overallType, inner := lastByte(inner)

    acts := action_none
	switch overallType {
	case kREC_TYPE_APPLICATION_DATA:
		conn.readBuf = append(conn.readBuf, inner...)
		acts |= action_none
    case kREC_TYPE_HANDSHAKE:
		// multiple handshake records conglommed together
        for len(inner) != 0 {
            len := readNum(24, inner[1:])
            payload := inner[:4+len]
            inner = inner[4+len:]
            acts |= conn.handleRecord(int(overallType), hdr, payload)
        }
	default:
		acts |= conn.handleRecord(int(overallType), hdr, inner)
    }
    return acts
}

func (conn *TLSConn) addToTranscript(hsr []byte) {
	conn.lastTranscript = conn.transcript
	conn.transcript = append(conn.transcript, hsr...)
}
