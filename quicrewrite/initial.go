package quicrewrite

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// version1 is QUIC v1 (RFC 9000); Initial packets of other versions are
// forwarded untouched.
const version1 = 0x00000001

// quicV1Salt is the Initial packet protection salt (RFC 9001 section 5.2).
var quicV1Salt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

const (
	sampleLen  = 16 // header protection sample (RFC 9001 section 5.4.2)
	aeadTagLen = 16 // AES-128-GCM tag
	maxCidLen  = 20
	nonceLen   = 12
)

// initialHeader is a parsed (still protected) QUIC v1 Initial packet header.
// pnLen/payloadStart are unknown until header protection is removed: the PN
// length bits of the first byte are themselves protected (RFC 9001 section
// 5.4.1), so they are filled in by unprotect, not by parse.
type initialHeader struct {
	firstByte    byte // protected first byte as it appears on the wire
	dcid, scid   []byte
	token        []byte
	length       uint64 // Length field: packet number + ciphertext incl. tag
	pnLen        int    // set by unprotect, 4 during serialize
	pnOffset     int    // offset of the protected packet number in the datagram
	payloadStart int    // pnOffset + pnLen, set by unprotect
	packetEnd    int    // pnOffset + length
}

// parseInitialHeader parses the protected header of a QUIC v1 Initial
// packet. The reserved and PN-length bits of firstByte are still protected;
// callers must unprotect before trusting them beyond the packet type.
func parseInitialHeader(d []byte) (initialHeader, error) {
	var h initialHeader
	if len(d) < 6 {
		return h, errors.New("quicrewrite: datagram too short for long header")
	}
	b0 := d[0]
	if b0&0xc0 != 0xc0 {
		return h, errors.New("quicrewrite: not a long header")
	}
	if b0>>4&0x03 != 0x00 {
		return h, errors.New("quicrewrite: not an Initial packet")
	}
	if binary.BigEndian.Uint32(d[1:5]) != version1 {
		return h, errors.New("quicrewrite: unsupported QUIC version")
	}
	h.firstByte = b0

	pos := 5
	dcidLen := int(d[pos])
	pos++
	if dcidLen > maxCidLen || pos+dcidLen > len(d) {
		return h, errors.New("quicrewrite: invalid DCID length")
	}
	h.dcid = d[pos : pos+dcidLen]
	pos += dcidLen

	if pos >= len(d) {
		return h, errors.New("quicrewrite: truncated after DCID")
	}
	scidLen := int(d[pos])
	pos++
	if scidLen > maxCidLen || pos+scidLen > len(d) {
		return h, errors.New("quicrewrite: invalid SCID length")
	}
	h.scid = d[pos : pos+scidLen]
	pos += scidLen

	tokenLen, pos2, err := readVarint(d, pos)
	if err != nil || pos2+int(tokenLen) > len(d) {
		return h, errors.New("quicrewrite: invalid token")
	}
	h.token = d[pos2 : pos2+int(tokenLen)]

	h.length, pos, err = readVarint(d, pos2+int(tokenLen))
	if err != nil {
		return h, errors.New("quicrewrite: invalid length")
	}
	h.pnOffset = pos
	h.pnLen = 4 // assumed maximum until unprotect reveals the real length
	h.payloadStart = pos + 4
	h.packetEnd = h.pnOffset + int(h.length)
	if h.packetEnd > len(d) {
		return h, errors.New("quicrewrite: packet length exceeds datagram")
	}
	// The HP sample always starts 4 bytes past the PN field start, assuming a
	// full-size PN (quic-go does the same); it must fit inside this packet.
	if h.pnOffset+4+sampleLen > h.packetEnd {
		return h, errors.New("quicrewrite: packet too small for header protection sample")
	}
	return h, nil
}

// serialize rebuilds the packet header with the given PN and payload size.
// reservedBits sets the two long-header reserved bits to 11 (CircumVolve
// "reserved bits" strategy).
func (h initialHeader) serialize(reservedBits bool, payloadLen int, pn uint64) []byte {
	firstByte := byte(0xc0 | (h.pnLen - 1))
	if reservedBits {
		firstByte |= 0x0c
	}
	out := make([]byte, 0, h.payloadStart+8)
	out = append(out, firstByte)
	out = binary.BigEndian.AppendUint32(out, version1)
	out = append(out, byte(len(h.dcid)))
	out = append(out, h.dcid...)
	out = append(out, byte(len(h.scid)))
	out = append(out, h.scid...)
	out = appendVarint(out, uint64(len(h.token)))
	out = append(out, h.token...)
	out = appendVarint(out, uint64(h.pnLen+payloadLen))
	for i := h.pnLen - 1; i >= 0; i-- {
		out = append(out, byte(pn>>uint(8*i)))
	}
	return out
}

// initialKeys holds the client Initial packet-protection keys derived from
// the DCID (RFC 9001 section 5.2).
type initialKeys struct {
	aead cipher.AEAD
	hp   cipher.Block // AES-ECB header protector
	iv   []byte
}

// hkdfExpandLabel implements the TLS 1.3 HKDF-Expand-Label (RFC 8446
// section 7.1) with an empty context.
func hkdfExpandLabel(secret []byte, label string, length int) ([]byte, error) {
	info := make([]byte, 0, 3+6+len(label))
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(6+len(label)))
	info = append(info, "tls13 "...)
	info = append(info, label...)
	info = append(info, 0)
	return hkdf.Expand(sha256.New, secret, string(info), length)
}

func deriveClientInitialKeys(dcid []byte) (initialKeys, error) {
	var k initialKeys
	initialSecret, err := hkdf.Extract(sha256.New, dcid, quicV1Salt)
	if err != nil {
		return k, err
	}
	clientSecret, err := hkdfExpandLabel(initialSecret, "client in", sha256.Size)
	if err != nil {
		return k, err
	}
	key, err := hkdfExpandLabel(clientSecret, "quic key", 16)
	if err != nil {
		return k, err
	}
	k.iv, err = hkdfExpandLabel(clientSecret, "quic iv", nonceLen)
	if err != nil {
		return k, err
	}
	hpKey, err := hkdfExpandLabel(clientSecret, "quic hp", 16)
	if err != nil {
		return k, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return k, err
	}
	k.aead, err = cipher.NewGCM(block)
	if err != nil {
		return k, err
	}
	k.hp, err = aes.NewCipher(hpKey)
	if err != nil {
		return k, err
	}
	return k, nil
}

// nonce derives the AEAD nonce: static IV XOR the 96-bit big-endian PN.
func (k initialKeys) nonce(pn uint64) []byte {
	n := make([]byte, nonceLen)
	copy(n, k.iv)
	var pnBE [8]byte
	binary.BigEndian.PutUint64(pnBE[:], pn)
	for i := 0; i < 8; i++ {
		n[4+i] ^= pnBE[i]
	}
	return n
}

func (k initialKeys) open(ciphertext, unprotectedHeader []byte, pn uint64) ([]byte, error) {
	return k.aead.Open(nil, k.nonce(pn), ciphertext, unprotectedHeader)
}

func (k initialKeys) seal(plaintext, unprotectedHeader []byte, pn uint64) []byte {
	return k.aead.Seal(nil, k.nonce(pn), plaintext, unprotectedHeader)
}

// applyHeaderProtection XORs the header protection mask onto the first byte
// (low 4 bits, long header) and the packet number. XOR is symmetric, so the
// same call protects and unprotects. sample must start 4 bytes past the PN
// field start.
func (k initialKeys) applyHeaderProtection(hdr []byte, pnOffset, pnLen int, sample []byte) {
	var mask [sampleLen]byte
	k.hp.Encrypt(mask[:], sample)
	hdr[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		hdr[pnOffset+i] ^= mask[1+i]
	}
}

// unprotect removes header protection from a copy of the header and returns
// the unprotected header plus the decoded packet number. The PN-length bits
// are themselves protected, so it does the quic-go two-step: assume a 4-byte
// PN for the sample offset and the mask, unprotect, then learn the real PN
// length and undo the wrongly unprotected ciphertext bytes. It fills in
// h.pnLen and h.payloadStart.
func (k initialKeys) unprotect(datagram []byte, h *initialHeader) ([]byte, uint64) {
	hdr := append([]byte(nil), datagram[:h.payloadStart]...)
	k.applyHeaderProtection(hdr, h.pnOffset, 4, datagram[h.pnOffset+4:h.pnOffset+4+sampleLen])
	h.pnLen = int(hdr[0]&0x03) + 1
	if h.pnLen != 4 {
		copy(hdr[h.pnOffset+h.pnLen:h.pnOffset+4], datagram[h.pnOffset+h.pnLen:h.pnOffset+4])
	}
	h.payloadStart = h.pnOffset + h.pnLen
	return hdr[:h.payloadStart], decodePacketNumber(hdr[h.pnOffset : h.pnOffset+h.pnLen])
}

// decodePacketNumber reads a truncated packet number as a plain big-endian
// integer. Client Initials have tiny PNs, so no RFC 9001 windowing is needed.
func decodePacketNumber(pn []byte) uint64 {
	var v uint64
	for _, b := range pn {
		v = v<<8 | uint64(b)
	}
	return v
}
