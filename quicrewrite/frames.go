package quicrewrite

// extractInitialCrypto walks the frames of a client Initial's plaintext and
// returns the reassembled CRYPTO stream. It requires the stream to start at
// offset 0 with no gaps and tolerates only PADDING, PING and CRYPTO frames;
// anything unexpected marks the packet unrewritable (fail-open).
func extractInitialCrypto(plaintext []byte) ([]byte, bool) {
	var data []byte
	var expected uint64
	pos := 0
	for pos < len(plaintext) {
		switch t := plaintext[pos]; t {
		case 0x00, 0x01: // PADDING, PING
			pos++
		case 0x06: // CRYPTO
			pos++
			off, p, err := readVarint(plaintext, pos)
			if err != nil {
				return nil, false
			}
			n, p2, err := readVarint(plaintext, p)
			if err != nil || n > uint64(len(plaintext)) || p2+int(n) > len(plaintext) {
				return nil, false
			}
			if off != expected {
				return nil, false
			}
			data = append(data, plaintext[p2:p2+int(n)]...)
			expected += n
			pos = p2 + int(n)
		default:
			return nil, false
		}
	}
	if len(data) == 0 {
		return nil, false
	}
	return data, true
}

// appendCryptoFrame appends a CRYPTO frame (RFC 9000 section 19.6).
func appendCryptoFrame(dst []byte, offset uint64, data []byte) []byte {
	dst = append(dst, 0x06)
	dst = appendVarint(dst, offset)
	dst = appendVarint(dst, uint64(len(data)))
	return append(dst, data...)
}

// ackInitial is an ACK frame acknowledging packet 0 — nonsense inside a
// client Initial, ignored by servers, but it derails censors that track ACK
// state (CircumVolve "prepend ACK" strategy).
var ackInitial = []byte{0x02, 0x00, 0x00, 0x00, 0x00}

const (
	// decoyCryptoOffset is the fake CRYPTO stream offset used by the decoy
	// strategy: far beyond any real handshake data yet small enough not to
	// trip server reassembly-buffer limits.
	decoyCryptoOffset = 1 << 20
	decoyCryptoLen    = 64
)

var decoyCryptoData = make([]byte, decoyCryptoLen)
