package tlsfrag

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

type recordedRecord struct {
	version [2]byte
	payload []byte
}

func parseRecords(t *testing.T, received []byte) []recordedRecord {
	t.Helper()
	var out []recordedRecord
	for len(received) > 0 {
		if len(received) < 5 {
			t.Fatalf("trailing bytes: %d", len(received))
		}
		rl := int(binary.BigEndian.Uint16(received[3:5]))
		if len(received) < 5+rl {
			t.Fatalf("truncated record: need %d bytes, have %d", 5+rl, len(received))
		}
		rec := recordedRecord{payload: append([]byte{}, received[5:5+rl]...)}
		rec.version[0] = received[1]
		rec.version[1] = received[2]
		out = append(out, rec)
		received = received[5+rl:]
	}
	return out
}

func sendOverPipe(t *testing.T, ch []byte, records, segments int, headerSplit, altRecordVer bool) []recordedRecord {
	t.Helper()
	_, sniPos, sniLen, _, err := ParseClientHello(ch)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	client, server := net.Pipe()
	defer server.Close()
	sent := make(chan error, 1)
	go func() {
		err := SendRecords(client, ch, sniPos, sniLen, records, segments, false, false, false, headerSplit, altRecordVer, 0)
		client.Close()
		sent <- err
	}()
	received, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-sent; err != nil {
		t.Fatalf("SendRecords: %v", err)
	}
	return parseRecords(t, received)
}

func reassembled(recs []recordedRecord) []byte {
	var payload []byte
	for _, r := range recs {
		payload = append(payload, r.payload...)
	}
	return payload
}

func TestSendRecords_HeaderSplit_FirstRecordInsideHandshakeHeader(t *testing.T) {
	ch := buildClientHelloForTest("github.com")
	recs := sendOverPipe(t, ch, 4, 1, true, false)

	if len(recs) != 4 {
		t.Fatalf("got %d records, want 4", len(recs))
	}
	if len(recs[0].payload) != 3 {
		t.Fatalf("first record payload = %d bytes, want 3 (inside handshake header)", len(recs[0].payload))
	}
	if !bytes.Equal(recs[0].payload, ch[5:8]) {
		t.Fatalf("first record payload %v, want %v", recs[0].payload, ch[5:8])
	}
	if !bytes.Equal(reassembled(recs), ch[5:]) {
		t.Errorf("reassembled payload differs from original: got %d bytes, want %d", len(reassembled(recs)), len(ch)-5)
	}
}

func TestSendRecords_HeaderSplit_TwoRecordsKeepsAllBytes(t *testing.T) {
	ch := buildClientHelloForTest("gist.github.com")
	recs := sendOverPipe(t, ch, 2, 1, true, false)

	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if len(recs[0].payload) >= 4 {
		t.Fatalf("first record payload = %d bytes, want <4", len(recs[0].payload))
	}
	if !bytes.Equal(reassembled(recs), ch[5:]) {
		t.Errorf("reassembled payload differs from original: got %d bytes, want %d", len(reassembled(recs)), len(ch)-5)
	}
}

func TestSendRecords_AltRecordVer_PerRecordVersions(t *testing.T) {
	ch := buildClientHelloForTest("github.com")
	recs := sendOverPipe(t, ch, 4, 1, false, true)

	if len(recs) != 4 {
		t.Fatalf("got %d records, want 4", len(recs))
	}
	if recs[0].version != [2]byte{0x03, 0x03} {
		t.Errorf("first record version = % X, want 03 03", recs[0].version)
	}
	for i := 1; i < len(recs); i++ {
		if recs[i].version != [2]byte{0x03, 0x01} {
			t.Errorf("record %d version = % X, want 03 01", i, recs[i].version)
		}
	}
	if !bytes.Equal(reassembled(recs), ch[5:]) {
		t.Errorf("reassembled payload differs from original: got %d bytes, want %d", len(reassembled(recs)), len(ch)-5)
	}
}

func TestSendRecords_HeaderSplitAndAltRecordVer_Composed(t *testing.T) {
	ch := buildClientHelloForTest("raw.githubusercontent.com")
	recs := sendOverPipe(t, ch, 4, 1, true, true)

	if len(recs) != 4 {
		t.Fatalf("got %d records, want 4", len(recs))
	}
	if len(recs[0].payload) != 3 {
		t.Fatalf("first record payload = %d bytes, want 3", len(recs[0].payload))
	}
	if recs[0].version != [2]byte{0x03, 0x03} {
		t.Errorf("first record version = % X, want 03 03", recs[0].version)
	}
	for i := 1; i < len(recs); i++ {
		if recs[i].version != [2]byte{0x03, 0x01} {
			t.Errorf("record %d version = % X, want 03 01", i, recs[i].version)
		}
	}
	if !bytes.Equal(reassembled(recs), ch[5:]) {
		t.Errorf("reassembled payload differs from original: got %d bytes, want %d", len(reassembled(recs)), len(ch)-5)
	}
}
