package proxy

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// startUDPRelaySocks5 runs a SOCKS5 server that supports UDP ASSOCIATE: it
// accepts the control connection, opens a UDP socket bound to the same host,
// and relays datagrams to the requested destination with SOCKS5 framing.
func startUDPRelaySocks5(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleUDPAssociate(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

func handleUDPAssociate(ctrl net.Conn) {
	defer ctrl.Close()

	// Greeting.
	head := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, head); err != nil {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(ctrl, methods); err != nil {
		return
	}
	if _, err := ctrl.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: VER CMD RSV then ATYP ADDR PORT. Only UDP ASSOCIATE is served.
	req := make([]byte, 3)
	if _, err := io.ReadFull(ctrl, req); err != nil {
		return
	}
	if req[1] != 0x03 {
		ctrl.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	// The client address in the request is ignored for UDP ASSOCIATE; the
	// server picks its own relay endpoint and reports it back.
	if _, err := readAssocTarget(ctrl); err != nil {
		return
	}

	relay, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		ctrl.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer relay.Close()

	bound := relay.LocalAddr().(*net.UDPAddr)
	resp := buildAssocReply(bound)
	if _, err := ctrl.Write(resp); err != nil {
		return
	}

	// Relay datagrams: forward each one to its target and return the reply
	// through the same client endpoint.
	done := make(chan struct{}, 1)

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65535)
		for {
			_ = relay.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, from, err := relay.ReadFrom(buf)
			if err != nil {
				return
			}
			payload, target, ok := parseAssocDatagram(buf[:n])
			if !ok {
				continue
			}
			go func(data []byte, dst string, client net.Addr) {
				up, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					return
				}
				defer up.Close()

				target, err := net.ResolveUDPAddr("udp", dst)
				if err != nil {
					return
				}
				if _, err := up.WriteTo(data, target); err != nil {
					return
				}
				reply := make([]byte, 65535)
				_ = up.SetReadDeadline(time.Now().Add(8 * time.Second))
				m, _, err := up.ReadFrom(reply)
				if err != nil {
					return
				}
				// The reply must go back to the client's source endpoint, not
				// to this relay's own address.
				_, _ = relay.WriteTo(buildAssocDatagram(reply[:m], client), client)
			}(payload, target, from)
		}
	}()

	// Tear down when the control connection goes away.
	go func() {
		io.Copy(io.Discard, ctrl)
		relay.Close()
	}()

	<-done
}

func readAssocTarget(conn net.Conn) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(conn, atyp[:]); err != nil {
		return "", err
	}
	var host string
	switch atyp[0] {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return "", err
		}
		buf := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		host = string(buf)
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	default:
		return "", errBadATYP
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return "", err
	}
	port := int(binary.BigEndian.Uint16(portBuf[:]))
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

var errBadATYP = errATYP{}

type errATYP struct{}

func (errATYP) Error() string { return "unsupported address type" }

func buildAssocReply(bound *net.UDPAddr) []byte {
	ip := bound.IP.To4()
	if ip == nil {
		ip = net.IPv4zero.To4()
	}
	out := make([]byte, 0, 10)
	out = append(out, 0x05, 0x00, 0x00, 0x01)
	out = append(out, ip...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(bound.Port))
	return append(out, port[:]...)
}

// parseAssocDatagram decodes RSV(2) FRAG(1) ATYP ADDR PORT DATA.
func parseAssocDatagram(b []byte) (payload []byte, target string, ok bool) {
	if len(b) < 5 {
		return nil, "", false
	}
	idx := 3 // skip RSV and FRAG

	var host string
	switch b[idx] {
	case 0x01:
		if len(b) < idx+7 {
			return nil, "", false
		}
		host = net.IP(b[idx+1 : idx+5]).String()
		idx += 5
	case 0x03:
		nameLen := int(b[idx+1])
		if len(b) < idx+2+nameLen+2 {
			return nil, "", false
		}
		host = string(b[idx+2 : idx+2+nameLen])
		idx += 2 + nameLen
	case 0x04:
		if len(b) < idx+19 {
			return nil, "", false
		}
		host = net.IP(b[idx+1 : idx+17]).String()
		idx += 17
	default:
		return nil, "", false
	}

	if len(b) < idx+2 {
		return nil, "", false
	}
	port := int(binary.BigEndian.Uint16(b[idx : idx+2]))
	idx += 2

	return b[idx:], net.JoinHostPort(host, strconv.Itoa(port)), true
}

// buildAssocDatagram encodes RSV(2) FRAG(1) ATYP ADDR PORT DATA.
func buildAssocDatagram(payload []byte, to net.Addr) []byte {
	udpAddr, _ := to.(*net.UDPAddr)
	if udpAddr == nil {
		return nil
	}

	out := make([]byte, 0, len(payload)+22)
	out = append(out, 0x00, 0x00, 0x00)

	if ip := udpAddr.IP.To4(); ip != nil {
		out = append(out, 0x01)
		out = append(out, ip...)
	} else {
		out = append(out, 0x04)
		out = append(out, udpAddr.IP.To16()...)
	}

	var port [2]byte
	binary.BigEndian.PutUint16(port[:], uint16(udpAddr.Port))
	out = append(out, port[:]...)
	return append(out, payload...)
}
