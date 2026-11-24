// Package quicrewrite rewrites client QUIC v1 Initial datagrams on the wire.
// It is the QUIC counterpart of TLS-RF: the Initial is decrypted with its
// DCID-derived keys, the CircumVolve paper's ClientHello strategies are
// applied to the CRYPTO stream, and the packet is re-sealed. Datagrams that
// are not rewritable client Initials pass through untouched (fail-open).
package quicrewrite

import (
	"encoding/binary"

	"github.com/SnishaperTeam/snishaper-core/tlsfrag"
)

// Strategies selects which CircumVolve QUIC techniques to apply. All are
// independent and composable except DoubleHello, which subsumes
// FragmentCrypto and PunycodeSNI.
type Strategies struct {
	ReservedBits   bool // set long-header reserved bits (0x0C) to 11
	PrependACK     bool // prepend a bogus ACK frame before the CRYPTO frame
	DecoyCrypto    bool // prepend a decoy CRYPTO frame at a huge stream offset
	FragmentCrypto bool // split the CRYPTO frame carrying the ClientHello
	DoubleHello    bool // real CH without SNI + second minimal CH with SNI
	PunycodeSNI    bool // rewrite SNI to xn--<hex> form
}

// AnyEnabled reports whether at least one strategy is active.
func (s Strategies) AnyEnabled() bool {
	return s.ReservedBits || s.PrependACK || s.DecoyCrypto || s.FragmentCrypto || s.DoubleHello || s.PunycodeSNI
}

// RewriteInitial applies s to a client QUIC v1 Initial datagram. It returns
// the rewritten datagram and true, or (nil, false) when the datagram must be
// forwarded unmodified: no strategy enabled, not a QUIC v1 Initial,
// undecryptable, or no ClientHello at CRYPTO offset 0. The input is never
// modified. Datagram growth (from added frames) is allowed; it never shrinks.
func RewriteInitial(datagram []byte, s Strategies) ([]byte, bool) {
	if !s.AnyEnabled() {
		return nil, false
	}
	h, err := parseInitialHeader(datagram)
	if err != nil {
		return nil, false
	}
	keys, err := deriveClientInitialKeys(h.dcid)
	if err != nil {
		return nil, false
	}

	// Unprotect a copy of the header; this also reveals the real PN length
	// (the PN-length bits are themselves protected).
	hdr, pn := keys.unprotect(datagram, &h)

	plaintext, err := keys.open(datagram[h.payloadStart:h.packetEnd], hdr, pn)
	if err != nil {
		return nil, false
	}
	ch, ok := extractInitialCrypto(plaintext)
	if !ok {
		return nil, false
	}

	newPlaintext := applyStrategies(plaintext, ch, s)
	newHdr := h.serialize(s.ReservedBits, len(newPlaintext)+aeadTagLen, pn)
	sealed := keys.seal(newPlaintext, newHdr, pn)

	packet := make([]byte, 0, len(newHdr)+len(sealed)+len(datagram)-h.packetEnd)
	packet = append(packet, newHdr...)
	packet = append(packet, sealed...)
	// Re-apply header protection with the new ciphertext's sample.
	newPnOffset := len(newHdr) - h.pnLen
	keys.applyHeaderProtection(packet, newPnOffset, h.pnLen, packet[newPnOffset+4:newPnOffset+4+sampleLen])
	// Coalesced packets after the Initial travel untouched.
	return append(packet, datagram[h.packetEnd:]...), true
}

// applyStrategies rebuilds the Initial plaintext: prepend frames, transform
// the ClientHello carrying CRYPTO frames, then pad back to at least the
// original plaintext size.
func applyStrategies(plaintext, ch []byte, s Strategies) []byte {
	target := len(plaintext)
	out := make([]byte, 0, target+128)
	if s.PrependACK {
		out = append(out, ackInitial...)
	}
	if s.DecoyCrypto {
		out = appendCryptoFrame(out, decoyCryptoOffset, decoyCryptoData)
	}

	chData := ch
	if s.PunycodeSNI {
		if rewritten, ok := punycodeClientHello(ch); ok {
			chData = rewritten
		}
	}

	switch {
	case s.DoubleHello:
		// First CH without SNI (censors parse it and pass), second minimal
		// CH carrying the real SNI for the server.
		ch1 := stripSNI(chData)
		out = appendCryptoFrame(out, 0, ch1)
		out = appendCryptoFrame(out, uint64(len(ch1)), minimalClientHello(sniName(chData)))
	case s.FragmentCrypto:
		half := len(chData) / 2
		out = appendCryptoFrame(out, 0, chData[:half])
		out = appendCryptoFrame(out, uint64(half), chData[half:])
	default:
		out = appendCryptoFrame(out, 0, chData)
	}

	for len(out) < target {
		out = append(out, 0x00) // PADDING back to the original plaintext size
	}
	return out
}

// wrapHandshake wraps raw ClientHello handshake bytes in a synthetic TLS
// record header so the tlsfrag rebuild helpers can parse them.
func wrapHandshake(ch []byte) []byte {
	rec := make([]byte, 5, 5+len(ch))
	rec[0] = 0x16
	rec[1] = 0x03
	rec[2] = 0x03
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(ch)))
	return append(rec, ch...)
}

// sniName returns the SNI hostname of a raw ClientHello (nil if absent).
func sniName(ch []byte) []byte {
	rec := wrapHandshake(ch)
	l, err := tlsfrag.ParseClientHelloLayout(rec)
	if err != nil || l.SniNameLen == 0 {
		return nil
	}
	return rec[l.SniNameAt : l.SniNameAt+l.SniNameLen]
}

// stripSNI removes the server_name extension; on failure it returns the
// ClientHello unchanged (fail-open).
func stripSNI(ch []byte) []byte {
	rec, err := tlsfrag.RemoveSNIExtension(wrapHandshake(ch))
	if err != nil {
		return ch
	}
	return rec[5:]
}

// punycodeClientHello rewrites the SNI to "xn--" + hex(name) (CircumVolve
// "punycode SNI" strategy: censors hardcode xn-- as harmless IDN).
func punycodeClientHello(ch []byte) ([]byte, bool) {
	name := sniName(ch)
	if len(name) == 0 {
		return nil, false
	}
	const hexDigits = "0123456789abcdef"
	enc := make([]byte, 0, 4+2*len(name))
	enc = append(enc, "xn--"...)
	for _, b := range name {
		enc = append(enc, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	rec, err := tlsfrag.ReplaceSNIName(wrapHandshake(ch), enc)
	if err != nil {
		return nil, false
	}
	return rec[5:], true
}

// minimalClientHello builds a second, SNI-only ClientHello carrying name for
// the CircumVolve "double CH" strategy.
func minimalClientHello(name []byte) []byte {
	listLen := 1 + 2 + len(name)
	extData := make([]byte, 0, 2+listLen)
	extData = binary.BigEndian.AppendUint16(extData, uint16(listLen))
	extData = append(extData, 0x00) // host_name
	extData = binary.BigEndian.AppendUint16(extData, uint16(len(name)))
	extData = append(extData, name...)

	var exts []byte
	exts = binary.BigEndian.AppendUint16(exts, 0x0000) // server_name
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(extData)))
	exts = append(exts, extData...)

	var body []byte
	body = append(body, 0x03, 0x03)             // legacy_version TLS 1.2
	body = append(body, make([]byte, 32)...)    // zero Random (differs from the real CH)
	body = append(body, 0x00)                   // empty session_id
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites: TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)             // compression_methods: null
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	ch := make([]byte, 4, 4+len(body))
	ch[0] = 0x01 // ClientHello
	ch[1] = byte(len(body) >> 16)
	ch[2] = byte(len(body) >> 8)
	ch[3] = byte(len(body))
	return append(ch, body...)
}
