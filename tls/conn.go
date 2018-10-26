package tls

import "fmt"

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
	raw                          Conn
	clientRandom                 [32]byte
	clientPrivKey                [kX25519KeyLen]byte
	clientPubKey                 [kX25519KeyLen]byte
	serverRandom                 [32]byte
	serverPubKey                 [kX25519KeyLen]byte
	transcript                   []byte
	secret0                      [32]byte
	clientHandshakeTrafficSecret [kSHA256OutLen]byte
	serverHandshakeTrafficSecret [kSHA256OutLen]byte
	computeKeysSalt              [kSHA256OutLen]byte
	serverSeq                    uint64
	clientSeq                    uint64
	clientWriteKey               [kAES128KeyLen]byte
	serverWriteKey               [kAES128KeyLen]byte
	clientWriteIV                [kGCMIVLen]byte
	serverWriteIV                [kGCMIVLen]byte
}

type action int
const (
	action_none = action(0)
	action_reset_sequence = action(1 << iota)
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

	hdrbuf := make([]byte, 5)
	for {
		n, err := conn.raw.Read(hdrbuf)
		if n == 5 {
			typ := int(hdrbuf[0])
			len := int(hdrbuf[3])<<8 | int(hdrbuf[4])
			payload := make([]byte, len)
			err = readFull(conn.raw, payload)
			if err != nil {
				return nil, err
			}
			acts := handleHSRecord(conn, typ, hdrbuf, payload)
			conn.serverSeq++
			if acts & action_reset_sequence != 0 {
				conn.serverSeq = 0
				conn.clientSeq = 0
			}
		}
		if err != nil {
			panic(err)
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
	conn.transcript = append(conn.transcript, rec[5:]...)
	return nil
}

func readFull(conn Conn, b []byte) error {
	for len(b) > 0 {
		n, err := conn.Read(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func (conn *TLSConn) Read([]byte) (n int, err error) {
	// xxx todo
	return 0, nil
}

func (conn *TLSConn) Write([]byte) (n int, err error) {
	// xxx todo
	return 0, nil
}

func (conn *TLSConn) Close() (err error) {
	return conn.raw.Close()
}

func handleHSRecord(conn *TLSConn, typ int, rechdr []byte, payload []byte) action {
	switch byte(typ) {
	case kREC_TYPE_CHANGE_CIPHER_SPEC:
		return handleChangeCipherSpec(conn, payload)
	case kREC_TYPE_ALERT:
		return handleAlert(conn, payload)
	case kREC_TYPE_HANDSHAKE:
		conn.transcript = append(conn.transcript, payload...)
		return handleHandshake(conn, payload)
	case kREC_TYPE_APPLICATION_DATA:
		return handleHandshakeCipherText(conn, rechdr, payload)
	default:
		panic("unrecognized record type")
	}
}

func xxxDump(label string, b []byte) {
	fmt.Printf("%s:\n", label)
	for i := 0; i < len(b); i++ {
		fmt.Printf("%02x", b[i])
		if i%16 == 15 {
			fmt.Printf("\n")
		} else {
			fmt.Printf(" ")
		}
	}
	fmt.Println()
}
