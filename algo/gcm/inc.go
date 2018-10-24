package gcm

func inc_32(b []byte) {
	if len(b) < 4 {
		panic("inc_32 b too short")
	}
	l := len(b)
	var n = uint32(b[l-1]) | uint32(b[l-2])<<8 | uint32(b[l-3])<<16 | uint32(b[l-4])<<24
	n++
	for i := 0; i < 4; i++ {
		b[l-i-1] = byte(n >> uint(8*i))
	}
}
