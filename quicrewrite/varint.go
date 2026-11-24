package quicrewrite

import "errors"

var errVarintTooShort = errors.New("quicrewrite: varint extends past end of data")

// appendVarint appends a QUIC variable-length integer (RFC 9000 section 16).
func appendVarint(dst []byte, v uint64) []byte {
	switch {
	case v < 0x40:
		return append(dst, byte(v))
	case v < 0x4000:
		return append(dst, byte(v>>8)|0x40, byte(v))
	case v < 0x40000000:
		return append(dst, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(dst, byte(v>>56)|0xc0, byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// readVarint reads a QUIC variable-length integer starting at pos.
func readVarint(b []byte, pos int) (uint64, int, error) {
	if pos >= len(b) {
		return 0, pos, errVarintTooShort
	}
	length := 1 << (b[pos] >> 6)
	if pos+length > len(b) {
		return 0, pos, errVarintTooShort
	}
	var v uint64 = uint64(b[pos] & 0x3f)
	for i := 1; i < length; i++ {
		v = v<<8 | uint64(b[pos+i])
	}
	return v, pos + length, nil
}
