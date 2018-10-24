package tls

import "fmt"

type Conn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() (error)
}

type TLSConn struct {
	raw           Conn
	clientRandom  [32]byte
	clientPrivKey [32]byte
	clientPubKey  [32]byte
	serverRandom  [32]byte
	serverPubKey  [32]byte
}

func NewConn(raw Conn, hostname string) (Conn, error) {
	conn := &TLSConn{raw: raw}
	rec, err := makeClientHello(conn, hostname)
	if err != nil {
		panic(err)
	}
	n, err := conn.raw.Write(rec)
	if err != nil {
		return nil, err
	}
	if n != len(rec) {
		panic("short write")
	}
	hdrbuf := make([]byte, 5)
	for {
		n, err = conn.raw.Read(hdrbuf)
		if n == 5 {
			typ := int(hdrbuf[0])
			len := int(hdrbuf[3])<<8 | int(hdrbuf[4])
			payload := make([]byte, len)
			err = readFull(conn.raw, payload)
			if err != nil {
				return nil, err
			}
			handleRecord(conn, typ, payload)
		}
		if err != nil {
			panic(err)
		}
	}
	return conn, nil
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

func handleRecord(conn *TLSConn, typ int, payload []byte) {
	switch byte(typ) {
	case kREC_TYPE_CHANGE_CIPHER_SPEC:
		handleChangeCipherSpec(conn, payload)
	case kREC_TYPE_ALERT:
		handleAlert(conn, payload)
	case kREC_TYPE_HANDSHAKE:
		handleHandshake(conn, payload)
	case kREC_TYPE_APPLICATION_DATA:
		handleApplicationData(conn, payload)
	default:
		panic("unrecognized record type")
	}
}

func xxxDump(label string, b []byte) {
	fmt.Printf("%s:\n", label)
	for i := 0; i < len(b); i++ {
		fmt.Printf("%02x", b[i])
		if i % 16 == 15 {
			fmt.Printf("\n")
		} else {
			fmt.Printf(" ")
		}
	}
	fmt.Println()
}
