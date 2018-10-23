package sha256_test

import (
	"testing"

	"encoding/hex"

	"github.com/syncsynchalt/tincan-tls/algo/sha256"
)

func h(sum []byte) string {
	return hex.EncodeToString(sum)
}

func b(s string) []byte {
	return []byte(s)
}

func TestEmpty(t *testing.T) {
	s := sha256.New()
	equals(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", h(s.Sum()))
}

func TestOne(t *testing.T) {
	s := sha256.New()
	s.Add(b("a"))
	equals(t, "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", h(s.Sum()))
}

func TestReset(t *testing.T) {
	s := sha256.New()
	s.Add(b("a"))
	equals(t, "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb", h(s.Sum()))
	s.Reset()
	s.Add(b("b"))
	equals(t, "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d", h(s.Sum()))
}

func TestString(t *testing.T) {
	str := "()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
	s := sha256.New()
	s.Add(b(str))
	equals(t, "e1de062261d80b7a9d13bc0c0504a67cd97670a849e5de5c9d68ce458b1f8728", h(s.Sum()))
}

func TestBoundaries(t *testing.T) {
	str := "()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
	for i := 0; i < len(str); i++ {
		t.Log("testing", i)
		s := sha256.New()
		s.Add(b(str[:i]))
		s.Add(b(str[i:]))
		equals(t, "e1de062261d80b7a9d13bc0c0504a67cd97670a849e5de5c9d68ce458b1f8728", h(s.Sum()))
	}
}

func TestMults(t *testing.T) {
	str := "()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
	for mult := 1; mult < len(str)/2; mult++ {
		t.Log("testing", mult)
		s := sha256.New()
		in := str
		for len(in) > mult {
			s.Add(b(in[:mult]))
			in = in[mult:]
		}
		s.Add(b(in))
		equals(t, "e1de062261d80b7a9d13bc0c0504a67cd97670a849e5de5c9d68ce458b1f8728", h(s.Sum()))
	}
}
