package sha256_test

import (
	"encoding/hex"
	"github.com/syncsynchalt/tincan-tls/algo/sha256"
	"strings"
	"testing"
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

func TestAllInOne(t *testing.T) {
	in := []byte("foobarbaz")
	expected, _ := hex.DecodeString("97df3588b5a3f24babc3851b372f0ba71a9dcdded43b14b9d06961bfc1707d9d")
	equals(t, expected, sha256.SumData(in))
}

func TestBig(t *testing.T) {
	in := `
01 00 00 82 03 03 69 94 d7 ee f2 25 94 fa d5 b5
a0 73 45 2c 9a a2 f9 1b 05 a6 dc f6 0c fe 2b 66
a0 50 70 32 b8 a1 00 00 02 13 01 01 00 00 57 00
2b 00 03 02 03 04 00 0a 00 04 00 02 00 1d 00 33
00 26 00 24 00 1d 00 20 19 ae d3 3c fc b5 0e 45
f9 21 af 0b ef 14 3d 74 18 82 33 69 1d de b7 81
e0 99 81 fa 25 3f de 31 00 00 00 0e 00 0c 00 00
09 31 32 37 2e 30 2e 30 2e 31 00 0d 00 08 00 06
04 01 04 03 08 04 02 00 00 56 03 03 d9 83 34 af
56 5c b7 cc a6 03 ff 05 f2 bc e6 2d b3 09 51 c3
02 98 92 46 86 88 fb e4 53 24 01 b0 00 13 01 00
00 2e 00 33 00 24 00 1d 00 20 f5 b5 3b d7 bb 01
7d 91 ee aa ea 9a d5 09 5e c1 de 5d 39 1c cf 6a
98 a5 f2 e4 89 9c 80 01 1c 5c 00 2b 00 02 03 04
08 00 00 02 00 00 0b 00 02 e4 00 00 02 e0 00 02
db 30 82 02 d7 30 82 01 bf a0 03 02 01 02 02 09
00 d5 38 3b 76 56 69 e0 a2 30 0d 06 09 2a 86 48
86 f7 0d 01 01 0b 05 00 30 17 31 15 30 13 06 03
55 04 03 0c 0c 65 61 38 35 35 32 65 64 64 63 30
66 30 1e 17 0d 31 38 31 30 32 35 32 33 30 38 33
34 5a 17 0d 32 38 31 30 32 32 32 33 30 38 33 34
5a 30 17 31 15 30 13 06 03 55 04 03 0c 0c 65 61
38 35 35 32 65 64 64 63 30 66 30 82 01 22 30 0d
06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01
0f 00 30 82 01 0a 02 82 01 01 00 f8 ba 42 6f 54
ea a2 22 ea 02 dd 02 9d c4 7a 3d 3a 2b 63 ce 84
c3 0e 62 03 e4 6b 9f ee 16 d7 a3 87 76 c6 b8 52
6c 77 bf c4 0c d0 16 53 47 00 f5 94 25 25 18 bd
40 40 b0 2e ed 60 c8 19 b1 98 22 b9 90 4d a5 d4
06 38 a3 8d 76 87 3a 25 7a 44 11 04 8a e8 c1 39
1b 53 cd 4e 60 e2 d7 ea 5e 83 92 58 3f a8 bd cd
52 1a 50 2f 25 27 39 c2 8b 93 0b 5d 53 cc a3 d5
5b 08 69 c5 a8 0c 5d 53 80 50 97 83 59 9d b5 3d
f3 7c 25 c0 6b c0 00 eb bb 0d 68 64 e9 13 03 d4
d6 b6 64 0e c1 74 de f1 c3 10 fe 66 a8 af 54 2e
ca 9c 2f 24 eb c5 24 d4 59 cf 8b e1 74 88 aa 06
df 37 cf 10 b7 3c da b3 85 34 ef 0d d1 06 8c 1d
6e eb 2c c9 8f e7 ca 79 4b be 7b ce 54 0d 17 f8
12 63 67 28 c7 fe ee 5c dc c4 ef 95 cd 23 fb 03
ae 48 87 b4 48 40 52 e3 46 02 6d bc 94 f0 04 7f
ec 3d 78 74 68 eb a9 df 94 95 95 02 03 01 00 01
a3 26 30 24 30 09 06 03 55 1d 13 04 02 30 00 30
17 06 03 55 1d 11 04 10 30 0e 82 0c 65 61 38 35
35 32 65 64 64 63 30 66 30 0d 06 09 2a 86 48 86
f7 0d 01 01 0b 05 00 03 82 01 01 00 05 2c eb f7
2f fd 6f bf af d0 7b c5 b1 ed 98 41 9f 99 eb 96
21 51 41 6c 15 cb 45 a4 59 00 d9 ae 34 02 dd 7a
30 62 63 4e 55 6d 0c aa 93 4f 74 09 03 9c 1a 53
ab 87 cc 7f 24 96 5c 5a 16 51 1f 35 82 f8 c2 05
bc 5b 75 69 44 c6 2a 35 97 bc b5 9e cf 82 f0 5d
af 6d cd be 29 38 f2 3c e7 bc f6 4f 9e 8e db a0
9b 43 57 ea b2 20 9a 18 0e e6 f0 2a f9 6e 71 54
7d 2d fc de ab 89 ac 32 fe 8f 60 88 4f 65 b1 e3
27 ab 1b 09 a0 7c dd 7e 22 67 54 82 79 26 05 95
16 f7 a4 54 cd 55 e2 b7 06 01 4c 0b 84 a8 53 d1
f2 82 1d 3a df 4b 90 3b 93 9f 44 fd d1 ec 91 bc
0b d0 99 77 17 a0 72 6f 63 97 a3 8a ae 35 d1 d4
3a 91 c2 14 d8 e8 dc 82 80 d6 91 79 35 7a 93 cc
12 95 4b 6b b6 05 61 1a 78 d7 96 4c 55 74 11 ca
39 9d 26 61 63 91 c8 45 1c 9f 66 dc ea 4b 55 fe
ea 28 e0 71 37 81 01 75 ed b9 d3 5d 00 00 0f 00
01 04 08 04 01 00 e6 9d ac 54 de 84 40 97 51 6d
31 85 ea 38 29 7d 38 e6 85 ee 91 82 d9 ca d9 78
09 7b 63 55 f1 6a 4f ef 16 c3 36 a8 3f 4f 46 ba
74 3c 4d c8 44 e6 b4 86 76 be a0 f3 99 a8 2a f3
72 e5 92 43 1d 52 98 d3 52 8d 3d cf 0e 18 3c f1
96 28 55 bb 9a 51 ca 23 50 7b 50 15 64 0a 2c 76
4d 0f a9 75 8f 3a 6e d3 9a b0 0b 0a 37 25 56 b5
f3 33 f1 4f 13 5b c6 80 8b 6d 66 b4 22 80 1c 37
28 f8 63 91 65 67 87 57 09 b3 5e 1c 21 07 d6 d3
fa 5e 39 a5 e9 8a c8 85 14 91 f9 3c 3c 2d 07 86
bf 0c a5 2e eb 0e 12 8d 1c ef c0 cb 94 84 63 23
41 3e 6c 1f ba 26 5b 73 ae 79 19 f1 5d e0 4a fb
f4 82 ce 7d 0b 30 70 df 27 b4 30 fa ca 52 6c f7
72 d8 d3 5d 5e 51 a1 d4 eb c5 0b 5d 33 27 c2 25
ca ce 67 c7 af 07 1b 87 6b ca 91 6b 88 6e a8 6c
27 ae f9 61 de df d1 cf 73 af b2 2c 1b 58 2f b4
7a 43 d5 47 5e 97 14 00 00 20 c2 c2 19 9d 55 c5
eb 9d 2f 33 89 71 0f 12 f9 09 3b b2 56 ce 80 4c
81 df 36 87 e1 ab 22 c5 3c 1d`
	in = strings.Join(strings.Fields(in), "")
	b, _ := hex.DecodeString(in)
	expected, _ := hex.DecodeString("e4841d104d7f26ad1a13f01d0cd4d5b4e949ecb93f0d07a75b402b4e97154a15")
	equals(t, expected, sha256.SumData(b))
}
