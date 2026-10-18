package subscription

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// websocketConn is a minimal RFC 6455 client used to carry VLESS over a
// WebSocket transport. It supports binary frames with client-side masking and
// transparently reassembles fragmented messages.
type websocketConn struct {
	net.Conn
	reader *bufio.Reader
	mask   bool

	// fragment holds the bytes of a message split across frames.
	fragment []byte
	// fragmentOpcode is the opcode of the message being assembled.
	fragmentOpcode byte
}

const (
	wsOpcodeContinuation = 0x0
	wsOpcodeText         = 0x1
	wsOpcodeBinary       = 0x2
	wsOpcodeClose        = 0x8
	wsOpcodePing         = 0x9
	wsOpcodePong         = 0xA
)

// WriteBinary sends payload as a single masked binary frame.
func (c *websocketConn) WriteBinary(payload []byte) error {
	header := buildFrameHeader(wsOpcodeBinary, len(payload), c.mask)
	if _, err := c.Conn.Write(header); err != nil {
		return err
	}
	if c.mask {
		maskKey := make([]byte, 4)
		if _, err := rand.Read(maskKey); err != nil {
			return err
		}
		masked := make([]byte, len(payload))
		for i := range payload {
			masked[i] = payload[i] ^ maskKey[i%4]
		}
		if _, err := c.Conn.Write(maskKey); err != nil {
			return err
		}
		if _, err := c.Conn.Write(masked); err != nil {
			return err
		}
		return nil
	}
	_, err := c.Conn.Write(payload)
	return err
}

func buildFrameHeader(opcode byte, length int, masked bool) []byte {
	header := make([]byte, 0, 14)
	header = append(header, 0x80|opcode) // FIN + opcode

	maskBit := byte(0)
	if masked {
		maskBit = 0x80
	}

	switch {
	case length < 126:
		header = append(header, maskBit|byte(length))
	case length <= 0xFFFF:
		header = append(header, maskBit|126)
		var buf [2]byte
		binary.BigEndian.PutUint16(buf[:], uint16(length))
		header = append(header, buf[:]...)
	default:
		header = append(header, maskBit|127)
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(length))
		header = append(header, buf[:]...)
	}
	return header
}

// ReadBinary reads the next data message, reassembling fragments and replying
// to pings transparently. Any bytes left over from a previous oversized read
// are returned first.
func (c *websocketConn) ReadBinary() ([]byte, error) {
	if len(c.fragment) > 0 {
		out := c.fragment
		c.fragment = nil
		return out, nil
	}

	for {
		opcode, payload, err := c.readFrame()
		if err != nil {
			return nil, err
		}

		switch opcode {
		case wsOpcodePing:
			// Reply with a pong carrying the same payload.
			if err := c.writeFrame(wsOpcodePong, payload); err != nil {
				return nil, err
			}
			continue
		case wsOpcodePong:
			continue
		case wsOpcodeClose:
			return nil, io.EOF
		case wsOpcodeContinuation:
			c.fragment = append(c.fragment, payload...)
			if len(c.fragment) == 0 {
				continue
			}
			out := c.fragment
			c.fragment = nil
			return out, nil
		default:
			if len(payload) == 0 && opcode != wsOpcodeText && opcode != wsOpcodeBinary {
				continue
			}
			return payload, nil
		}
	}
}

func (c *websocketConn) readFrame() (byte, []byte, error) {
	var head [2]byte
	if _, err := io.ReadFull(c.reader, head[:]); err != nil {
		return 0, nil, err
	}

	opcode := head[0] & 0x0F
	masked := head[1]&0x80 != 0
	length := int(head[1] & 0x7F)

	switch length {
	case 126:
		var buf [2]byte
		if _, err := io.ReadFull(c.reader, buf[:]); err != nil {
			return 0, nil, err
		}
		length = int(binary.BigEndian.Uint16(buf[:]))
	case 127:
		var buf [8]byte
		if _, err := io.ReadFull(c.reader, buf[:]); err != nil {
			return 0, nil, err
		}
		length = int(binary.BigEndian.Uint64(buf[:]))
	}

	if length < 0 || length > 32*1024*1024 {
		return 0, nil, fmt.Errorf("websocket: frame too large: %d", length)
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(c.reader, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return opcode, payload, nil
}

func (c *websocketConn) writeFrame(opcode byte, payload []byte) error {
	header := buildFrameHeader(opcode, len(payload), c.mask)
	if _, err := c.Conn.Write(header); err != nil {
		return err
	}
	if !c.mask {
		_, err := c.Conn.Write(payload)
		return err
	}

	maskKey := make([]byte, 4)
	if _, err := rand.Read(maskKey); err != nil {
		return err
	}
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ maskKey[i%4]
	}
	if _, err := c.Conn.Write(maskKey); err != nil {
		return err
	}
	_, err := c.Conn.Write(masked)
	return err
}

func (c *websocketConn) Read(p []byte) (int, error) {
	msg, err := c.ReadBinary()
	if err != nil {
		return 0, err
	}
	n := copy(p, msg)
	if n < len(msg) {
		// Keep the remainder for the next read.
		c.fragment = msg[n:]
	}
	return n, nil
}

func (c *websocketConn) Write(p []byte) (int, error) {
	if err := c.WriteBinary(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *websocketConn) Close() error {
	_ = c.writeFrame(wsOpcodeClose, nil)
	return c.Conn.Close()
}

func (c *websocketConn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(t) }
func (c *websocketConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *websocketConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }
func (c *websocketConn) LocalAddr() net.Addr                { return c.Conn.LocalAddr() }
func (c *websocketConn) RemoteAddr() net.Addr               { return c.Conn.RemoteAddr() }

var _ net.Conn = (*websocketConn)(nil)
