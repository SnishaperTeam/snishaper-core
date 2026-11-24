package tlsfrag

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"
)

const (
	TlsRecordHeaderLen       = 5
	TlsHandshakeRecord       = 22
	TlsFragmentReadWait      = 10 * time.Second
	DefaultTLSRFNumRecords   = 4
	DefaultTLSRFNumSegments  = 1
	DefaultTLSRFSendInterval = 50 * time.Millisecond
	DefaultTLSRFModMinorVer  = true
	DefaultTLSRFOOB          = false
	DefaultTLSRFOOBEx        = false
	DefaultTLSRFHeaderSplit  = false
	DefaultTLSRFAltRecordVer = false
)

// ReadInitialTLSRecord reads the first complete TLS record from the connection.
func ReadInitialTLSRecord(conn net.Conn) ([]byte, error) {
	header := make([]byte, TlsRecordHeaderLen)
	_ = conn.SetReadDeadline(time.Now().Add(TlsFragmentReadWait))
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	record := make([]byte, TlsRecordHeaderLen+recordLen)
	copy(record, header)
	if recordLen > 0 {
		if _, err := io.ReadFull(conn, record[TlsRecordHeaderLen:]); err != nil {
			return nil, err
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	return record, nil
}

// FindLastDot returns the offset of the last dot inside the SNI hostname.
func FindLastDot(data []byte, sniPos, sniLen int) (offset int, found bool) {
	for i := sniPos + sniLen; i >= sniPos; i-- {
		if data[i] == '.' {
			return i, true
		}
	}
	return sniLen/2 + sniPos, false
}

// ParseClientHello extracts the protocol version, SNI location and key-share presence from a ClientHello.
func ParseClientHello(data []byte) (prtVer []byte, sniPos int, sniLen int, hasKeyShare bool, err error) {
	var l ClientHelloLayout
	l, err = ParseClientHelloLayout(data)
	if err != nil {
		return nil, -1, 0, false, err
	}
	if l.SniExtStart == -1 {
		return l.PrtVer, -1, 0, l.HasKeyShare, nil
	}
	return l.PrtVer, l.SniNameAt, l.SniNameLen, l.HasKeyShare, nil
}

// SendRecords sends the ClientHello split into records and segments with the configured shaping options.
//
// headerSplit places the first record boundary inside the 4-byte handshake
// header (first record payload <4 bytes); altRecordVer sends the first record
// with version 0x0303 and the remaining records with 0x0301. Both are
// CircumVolve (CCS'26) strategies that re-frame bytes without altering the
// handshake content, and only apply when records >= 2.
func SendRecords(conn net.Conn, clientHello []byte, offset, length, records, segments int, oob, oobex, modMinorVer, headerSplit, altRecordVer bool, interval time.Duration) error {
	if modMinorVer && len(clientHello) >= 3 {
		clientHello[2] = 0x04
	}

	if records == 1 {
		if oobex {
			if err := SendWithOOB(conn, clientHello[:15], clientHello[15]); err != nil {
				return fmt.Errorf("oob 1: %w", err)
			}
			if err := SendWithOOB(conn, clientHello[16:20], 0x0); err != nil {
				return fmt.Errorf("oob 2: %w", err)
			}
			if interval > 0 {
				time.Sleep(interval)
			}
			clientHello = clientHello[20:]
		}
		if segments == 1 {
			if _, err := conn.Write(clientHello); err != nil {
				return fmt.Errorf("send remaining data: %w", err)
			}
			return nil
		}
		leftSegments := segments / 2
		rightSegments := segments - leftSegments
		packets := make([][]byte, 0, segments)
		cut, _ := FindLastDot(clientHello, offset-20, length)
		splitAndAppend(clientHello[:cut], nil, leftSegments, &packets)
		splitAndAppend(clientHello[cut:], nil, rightSegments, &packets)
		for i, packet := range packets {
			if i == 0 && oob {
				if err := SendWithOOB(conn, packet, 0x0); err != nil {
					return fmt.Errorf("oob: %w", err)
				}
			} else {
				if _, err := conn.Write(packet); err != nil {
					return fmt.Errorf("write packet %d: %w", i+1, err)
				}
			}
			if interval > 0 {
				time.Sleep(interval)
			}
		}
		return nil
	}

	leftChunks := records / 2
	rightChunks := records - leftChunks
	chunks := make([][]byte, 0, records)
	cut, _ := FindLastDot(clientHello, offset, length)
	header := clientHello[:3]
	if headerSplit && records >= 2 && len(clientHello) > 8 && cut > 8 {
		// Header split: the first record ends inside the handshake header,
		// so the last handshake-length byte opens the second record.
		chunks = append(chunks, makeRecord(header, clientHello[5:8]))
		remaining := records - 1
		if remaining == 1 {
			chunks = append(chunks, makeRecord(header, clientHello[8:]))
		} else {
			restLeft := remaining / 2
			if restLeft < 1 {
				restLeft = 1
			}
			restRight := remaining - restLeft
			splitAndAppend(clientHello[8:cut], header, restLeft, &chunks)
			splitAndAppend(clientHello[cut:], header, restRight, &chunks)
		}
	} else {
		splitAndAppend(clientHello[5:cut], header, leftChunks, &chunks)
		splitAndAppend(clientHello[cut:], header, rightChunks, &chunks)
	}

	if altRecordVer && len(chunks) >= 2 {
		// Per-record version bytes: 0x0303 on the first record, 0x0301 on
		// the rest. Overrides modMinorVer's single-version mutation.
		for i := range chunks {
			chunks[i][1] = 0x03
			if i == 0 {
				chunks[i][2] = 0x03
			} else {
				chunks[i][2] = 0x01
			}
		}
	}

	merged := make([]byte, 0, records*5+len(clientHello))
	for _, c := range chunks {
		merged = append(merged, c...)
	}

	if oobex {
		if err := SendWithOOB(conn, merged[:15], merged[15]); err != nil {
			return fmt.Errorf("oob 1: %w", err)
		}
		if err := SendWithOOB(conn, merged[16:20], 0x0); err != nil {
			return fmt.Errorf("oob 2: %w", err)
		}
		if interval > 0 {
			time.Sleep(interval)
		}
		merged = merged[20:]
	}
	if segments == 1 || len(merged) <= segments {
		_, err := conn.Write(merged)
		return err
	}

	base := len(merged) / segments
	for i := 0; i < segments; i++ {
		start := i * base
		end := start + base
		if i == segments-1 {
			end = len(merged)
		}
		if i == 0 && oob {
			if err := SendWithOOB(conn, merged[start:end], 0x0); err != nil {
				return fmt.Errorf("oob: %w", err)
			}
		} else {
			if _, err := conn.Write(merged[start:end]); err != nil {
				return fmt.Errorf("write segment %d: %w", i+1, err)
			}
		}
		if interval > 0 {
			time.Sleep(interval)
		}
	}
	return nil
}

func splitAndAppend(data, header []byte, n int, result *[][]byte) {
	if n <= 0 {
		return
	}
	addHeader := header != nil
	if n == 1 || len(data) < n {
		if addHeader {
			*result = append(*result, makeRecord(header, data))
		} else {
			*result = append(*result, data)
		}
		return
	}
	base := len(data) / n
	for i := 0; i < n; i++ {
		var part []byte
		if i == n-1 {
			part = data[i*base:]
		} else {
			part = data[i*base : (i+1)*base]
		}
		if addHeader {
			*result = append(*result, makeRecord(header, part))
		} else {
			*result = append(*result, part)
		}
	}
}

func makeRecord(header, payload []byte) []byte {
	rec := make([]byte, 5+len(payload))
	copy(rec[:3], header)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(payload)))
	copy(rec[5:], payload)
	return rec
}

// GetRawConn unwraps conn to a syscall.RawConn.
func GetRawConn(conn net.Conn) (syscall.RawConn, error) {
	rawConnProvider, ok := conn.(syscall.Conn)
	if !ok {
		return nil, errors.New("connection does not support raw access")
	}
	return rawConnProvider.SyscallConn()
}

// IsUseOfClosedConn reports whether err is a use-of-closed-connection error.
func IsUseOfClosedConn(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed")
}
