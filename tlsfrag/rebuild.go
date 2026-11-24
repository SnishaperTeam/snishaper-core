package tlsfrag

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// maxTLSRecordPayload is the maximum plaintext a TLS record may carry (RFC 8446).
const maxTLSRecordPayload = 16384

// ClientHelloLayout locates the length fields needed to rebuild a ClientHello
// record in place. Offsets are absolute positions inside the record.
type ClientHelloLayout struct {
	RecordLenAt    int // 2-byte record length field (always 3)
	HandshakeLenAt int // 3-byte handshake length field (always 6)
	RecordEnd      int // 5 + record length
	ExtTotalLenAt  int // 2-byte extensions total length field (-1 if absent)
	ExtBlockStart  int
	PrtVer         []byte
	HasKeyShare    bool
	SniExtStart    int // offset of the server_name extension type field (-1 if absent)
	SniExtLen      int // full extension size incl. type+length header
	SniNameAt      int
	SniNameLen     int
}

// ParseClientHelloLayout walks a TLS record and returns the byte offsets of
// every field a rebuild needs. It accepts the same inputs as ParseClientHello
// and reports the same errors.
func ParseClientHelloLayout(data []byte) (ClientHelloLayout, error) {
	const (
		handshakeHeaderLen       = 4
		handshakeTypeClientHello = 0x01
		extTypeSNI               = 0x0000
		extTypeKeyShare          = 0x0033
	)

	var l ClientHelloLayout
	l.SniExtStart = -1
	l.ExtTotalLenAt = -1

	if len(data) < TlsRecordHeaderLen {
		return l, errors.New("TLS record too short")
	}
	l.RecordLenAt = 3
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	l.RecordEnd = TlsRecordHeaderLen + recordLen
	if len(data) < l.RecordEnd {
		return l, errors.New("record length exceeds data size")
	}
	offset := TlsRecordHeaderLen

	if recordLen < handshakeHeaderLen {
		return l, errors.New("handshake message too short")
	}
	if data[offset] != handshakeTypeClientHello {
		return l, fmt.Errorf("not a ClientHello handshake (type=%d)", data[offset])
	}
	l.HandshakeLenAt = offset + 1
	handshakeLen := int(uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3]))
	if handshakeLen+handshakeHeaderLen > recordLen {
		return l, errors.New("handshake length exceeds record length")
	}
	offset += handshakeHeaderLen

	if handshakeLen < 2+32+1 {
		return l, errors.New("ClientHello too short for mandatory fields")
	}
	l.PrtVer = data[offset : offset+2]
	offset += 2
	offset += 32
	if offset >= len(data) {
		return l, errors.New("unexpected end after Random")
	}
	sessionIDLen := int(data[offset])
	offset++
	if offset+sessionIDLen > len(data) {
		return l, errors.New("session_id length exceeds data")
	}
	offset += sessionIDLen

	if offset+2 > len(data) {
		return l, errors.New("cannot read cipher_suites length")
	}
	csLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+csLen > len(data) {
		return l, errors.New("cipher_suites exceed data")
	}
	offset += csLen

	if offset >= len(data) {
		return l, errors.New("cannot read compression_methods length")
	}
	compMethodsLen := int(data[offset])
	offset++
	if offset+compMethodsLen > len(data) {
		return l, errors.New("compression_methods exceed data")
	}
	offset += compMethodsLen

	if offset+2 > len(data) {
		return l, nil
	}
	extTotalLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	l.ExtTotalLenAt = offset
	offset += 2
	l.ExtBlockStart = offset
	if offset+extTotalLen > len(data) {
		return l, errors.New("extensions length exceeds data")
	}
	extensionsEnd := offset + extTotalLen

	for offset+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		extDataStart := offset + 4
		extDataEnd := extDataStart + extLen

		if extDataEnd > extensionsEnd {
			return l, errors.New("extension length exceeds extensions block")
		}

		if extType == extTypeKeyShare {
			l.HasKeyShare = true
			if l.SniExtStart != -1 {
				return l, nil
			}
		}

		if l.SniExtStart == -1 && extType == extTypeSNI {
			if extLen < 2 {
				return l, errors.New("malformed SNI extension")
			}
			listLen := int(binary.BigEndian.Uint16(data[extDataStart : extDataStart+2]))
			if listLen+2 != extLen {
				return l, errors.New("SNI list length field mismatch")
			}
			cursor := extDataStart + 2
			if cursor+3 > extDataEnd {
				return l, errors.New("SNI entry too short")
			}
			if data[cursor] != 0 {
				return l, errors.New("unsupported SNI name type")
			}
			nameLen := int(binary.BigEndian.Uint16(data[cursor+1 : cursor+3]))
			nameStart := cursor + 3
			nameEnd := nameStart + nameLen
			if nameEnd > extDataEnd {
				return l, errors.New("SNI name length exceeds extension")
			}
			l.SniExtStart = offset
			l.SniExtLen = extLen + 4
			l.SniNameAt = nameStart
			l.SniNameLen = nameLen
			if l.HasKeyShare {
				return l, nil
			}
		}
		offset = extDataEnd
	}
	return l, nil
}

// parseRebuildableLayout parses a record and enforces the structural
// preconditions the rebuild helpers rely on: the ClientHello is the only
// handshake message in the record and the extensions block fills the
// handshake exactly.
func parseRebuildableLayout(record []byte) (ClientHelloLayout, error) {
	l, err := ParseClientHelloLayout(record)
	if err != nil {
		return l, err
	}
	if l.SniExtStart == -1 {
		return l, errors.New("no server_name extension")
	}
	if l.ExtTotalLenAt == -1 {
		return l, errors.New("no extensions block")
	}
	handshakeLen := int(uint32(record[l.HandshakeLenAt])<<16 | uint32(record[l.HandshakeLenAt+1])<<8 | uint32(record[l.HandshakeLenAt+2]))
	extTotalLen := int(binary.BigEndian.Uint16(record[l.ExtTotalLenAt : l.ExtTotalLenAt+2]))
	if l.ExtBlockStart+extTotalLen != TlsRecordHeaderLen+handshakeHeaderLenBytes+handshakeLen {
		return l, errors.New("extensions block does not fill the handshake message")
	}
	if l.RecordEnd != l.ExtBlockStart+extTotalLen {
		return l, errors.New("record contains trailing data after the ClientHello")
	}
	return l, nil
}

const handshakeHeaderLenBytes = 4

// fixupLengths updates the record, handshake and extensions total length
// fields after a delta change in ClientHello body size.
func fixupLengths(out []byte, l ClientHelloLayout, delta int) {
	recordLen := int(binary.BigEndian.Uint16(out[l.RecordLenAt:l.RecordLenAt+2])) + delta
	binary.BigEndian.PutUint16(out[l.RecordLenAt:l.RecordLenAt+2], uint16(recordLen))

	hs := int(uint32(out[l.HandshakeLenAt])<<16 | uint32(out[l.HandshakeLenAt+1])<<8 | uint32(out[l.HandshakeLenAt+2])) + delta
	out[l.HandshakeLenAt] = byte(hs >> 16)
	out[l.HandshakeLenAt+1] = byte(hs >> 8)
	out[l.HandshakeLenAt+2] = byte(hs)

	extTotal := int(binary.BigEndian.Uint16(out[l.ExtTotalLenAt:l.ExtTotalLenAt+2])) + delta
	binary.BigEndian.PutUint16(out[l.ExtTotalLenAt:l.ExtTotalLenAt+2], uint16(extTotal))
}

// AppendPaddingExtension appends an RFC 7685 padding extension with n zero
// bytes to the ClientHello, forcing the record to grow so that TCP must
// segment it (CircumVolve "padding" strategy). n is capped so the record
// stays within the TLS record size limit.
func AppendPaddingExtension(record []byte, n int) ([]byte, error) {
	l, err := parseRebuildableLayout(record)
	if err != nil {
		return nil, err
	}
	if n < 0 {
		n = 0
	}
	recordLen := int(binary.BigEndian.Uint16(record[l.RecordLenAt : l.RecordLenAt+2]))
	if max := maxTLSRecordPayload - recordLen - 4; n > max {
		n = max
	}
	if n < 0 {
		n = 0
	}

	out := make([]byte, 0, len(record)+4+n)
	out = append(out, record...)
	out = append(out, 0x00, 0x15) // extension type: padding (RFC 7685)
	out = append(out, byte(n>>8), byte(n))
	out = append(out, make([]byte, n)...)
	fixupLengths(out, l, 4+n)
	return out, nil
}

// TrailingDotSNI appends a trailing dot to the SNI hostname so exact-match
// SNI blocklists miss the FQDN (CircumVolve "trailing dot" strategy).
func TrailingDotSNI(record []byte) ([]byte, error) {
	l, err := parseRebuildableLayout(record)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(record)+1)
	out = append(out, record[:l.SniNameAt+l.SniNameLen]...)
	out = append(out, '.')
	out = append(out, record[l.SniNameAt+l.SniNameLen:]...)

	// SNI name length field (2 bytes, big endian) sits right before the name.
	nameLenAt := l.SniNameAt - 2
	nameLen := int(binary.BigEndian.Uint16(out[nameLenAt:nameLenAt+2])) + 1
	binary.BigEndian.PutUint16(out[nameLenAt:nameLenAt+2], uint16(nameLen))
	// SNI list length field sits at extension data start (ext type+len header is 4 bytes).
	listLenAt := l.SniExtStart + 4
	listLen := int(binary.BigEndian.Uint16(out[listLenAt:listLenAt+2])) + 1
	binary.BigEndian.PutUint16(out[listLenAt:listLenAt+2], uint16(listLen))
	// Extension length field.
	extLenAt := l.SniExtStart + 2
	extLen := int(binary.BigEndian.Uint16(out[extLenAt:extLenAt+2])) + 1
	binary.BigEndian.PutUint16(out[extLenAt:extLenAt+2], uint16(extLen))
	fixupLengths(out, l, 1)
	return out, nil
}

// ReplaceSNIName swaps the SNI hostname for name, fixing up the record,
// handshake, extensions, SNI list and SNI name length fields for the size
// delta. Used by the QUIC punycode SNI strategy.
func ReplaceSNIName(record []byte, name []byte) ([]byte, error) {
	l, err := parseRebuildableLayout(record)
	if err != nil {
		return nil, err
	}
	delta := len(name) - l.SniNameLen

	out := make([]byte, 0, len(record)+delta)
	out = append(out, record[:l.SniNameAt]...)
	out = append(out, name...)
	out = append(out, record[l.SniNameAt+l.SniNameLen:]...)

	// SNI name length field (2 bytes, big endian) sits right before the name.
	nameLenAt := l.SniNameAt - 2
	binary.BigEndian.PutUint16(out[nameLenAt:nameLenAt+2], uint16(len(name)))
	// SNI list length field sits at extension data start (ext type+len header is 4 bytes).
	listLenAt := l.SniExtStart + 4
	listLen := int(binary.BigEndian.Uint16(out[listLenAt:listLenAt+2])) + delta
	binary.BigEndian.PutUint16(out[listLenAt:listLenAt+2], uint16(listLen))
	// Extension length field.
	extLenAt := l.SniExtStart + 2
	extLen := int(binary.BigEndian.Uint16(out[extLenAt:extLenAt+2])) + delta
	binary.BigEndian.PutUint16(out[extLenAt:extLenAt+2], uint16(extLen))
	fixupLengths(out, l, delta)
	return out, nil
}

// RemoveSNIExtension removes the server_name extension from the ClientHello
// (CircumVolve "hidden SNI" strategy). The server falls back to its default
// certificate; only works for deployments that serve the right cert without
// SNI — verified for Cloudflare and Google in the paper.
func RemoveSNIExtension(record []byte) ([]byte, error) {
	l, err := parseRebuildableLayout(record)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(record)-l.SniExtLen)
	out = append(out, record[:l.SniExtStart]...)
	out = append(out, record[l.SniExtStart+l.SniExtLen:]...)
	fixupLengths(out, l, -l.SniExtLen)
	return out, nil
}
