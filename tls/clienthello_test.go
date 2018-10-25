package tls

import (
	"fmt"
	"testing"
)

func TestClientHello(t *testing.T) {
	c := &TLSConn{}
	rec, err := makeClientHello(c, "host.name")
	ok(t, err)

	for i := range rec {
		fmt.Printf("%02x", rec[i])
		if i%16 == 15 {
			fmt.Printf("\n")
		} else {
			fmt.Printf(" ")
		}
	}
	fmt.Printf("\n")
}
