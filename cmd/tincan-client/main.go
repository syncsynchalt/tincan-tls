package main

import (
	"fmt"
	"github.com/syncsynchalt/tincan-tls/tls"
	"io"
	"net"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s host port\n", os.Args[0])
		os.Exit(1)
	}
	host := os.Args[1]
	port := os.Args[2]
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		panic(err)
	}

	tlsConn, err := tls.NewConn(conn, host)
	if err != nil {
		panic(err)
	}

	go func() {
		rbuf := make([]byte, 102400)
		for {
			n, err := tlsConn.Read(rbuf)
			if n != 0 {
				os.Stdout.Write(rbuf[:n])
			}
			if n == 0 || err == io.EOF {
				break
			}
			if err != nil {
				panic(err)
			}
		}
		fmt.Fprintln(os.Stderr, "EOF from peer")
		tlsConn.Close()
		os.Exit(0)
	}()

	wbuf := make([]byte, 102400)
	for {
		n, err := os.Stdin.Read(wbuf)
		if n != 0 {
			tlsConn.Write(wbuf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}
	}

	tlsConn.Close()
}
