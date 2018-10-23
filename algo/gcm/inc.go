package gcm

func inc_32(b []byte) {
	if len(b) < 4 {
		panic("inc_32 b too short")
	}
	l := len(b)
	var n = uint32(b[l-1]) | uint32(b[l-2]) << 8 | uint32(b[l-3]) << 16 | uint32(b[l-4]) << 24
	n++
	b[l-1] = byte(n); b[l-2] = byte(n>>8); b[l-3] = byte(n>>16); b[l-4] = byte(n>>24)
}
