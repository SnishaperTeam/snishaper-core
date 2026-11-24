package tlsfrag

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// checkRecordInvariants verifies that every length field inside the record
// matches the actual byte layout: a record that passes this check can be
// re-parsed and re-fragmented as a structurally valid ClientHello.
func checkRecordInvariants(t *testing.T, record []byte) ClientHelloLayout {
	t.Helper()
	l, err := ParseClientHelloLayout(record)
	if err != nil {
		t.Fatalf("layout: %v", err)
	}
	recordLen := int(binary.BigEndian.Uint16(record[3:5]))
	if recordLen != len(record)-5 {
		t.Fatalf("record length field = %d, want %d", recordLen, len(record)-5)
	}
	handshakeLen := int(uint32(record[6])<<16 | uint32(record[7])<<8 | uint32(record[8]))
	if handshakeLen+4 != recordLen {
		t.Fatalf("handshake length %d does not fill record payload %d", handshakeLen+4, recordLen)
	}
	if l.ExtTotalLenAt == -1 {
		t.Fatal("extensions block missing after rebuild")
	}
	extTotal := int(binary.BigEndian.Uint16(record[l.ExtTotalLenAt : l.ExtTotalLenAt+2]))
	if l.ExtBlockStart+extTotal != 9+handshakeLen {
		t.Fatalf("extensions block %d bytes does not fill handshake message ending at %d", extTotal, 9+handshakeLen)
	}
	return l
}

func TestTrailingDotSNI_AppendsDotAndFixesLengths(t *testing.T) {
	for _, host := range []string{"github.com", "gist.github.com"} {
		t.Run(host, func(t *testing.T) {
			ch := buildClientHelloForTest(host)
			out, err := TrailingDotSNI(ch)
			if err != nil {
				t.Fatalf("TrailingDotSNI: %v", err)
			}
			l := checkRecordInvariants(t, out)
			want := []byte(host + ".")
			got := out[l.SniNameAt : l.SniNameAt+l.SniNameLen]
			if !bytes.Equal(got, want) {
				t.Fatalf("SNI = %q, want %q", got, want)
			}
			if _, sniPos, sniLen, _, err := ParseClientHello(out); err != nil || sniPos <= 0 || sniLen != len(want) {
				t.Fatalf("re-parse failed: pos=%d len=%d err=%v", sniPos, sniLen, err)
			}
		})
	}
}

func TestTrailingDotSNI_DoesNotMutateInput(t *testing.T) {
	ch := buildClientHelloForTest("github.com")
	orig := append([]byte{}, ch...)
	if _, err := TrailingDotSNI(ch); err != nil {
		t.Fatalf("TrailingDotSNI: %v", err)
	}
	if !bytes.Equal(ch, orig) {
		t.Fatal("input record was mutated")
	}
}

func TestTrailingDotSNI_RejectsRecordsWithoutSNI(t *testing.T) {
	// A minimal non-TLS buffer must be rejected, not panic.
	if _, err := TrailingDotSNI([]byte{0x16, 0x03, 0x01, 0x00, 0x00}); err == nil {
		t.Fatal("expected error for truncated record")
	}
}

func TestRemoveSNIExtension_HidesServerName(t *testing.T) {
	ch := buildClientHelloForTest("github.com")
	out, err := RemoveSNIExtension(ch)
	if err != nil {
		t.Fatalf("RemoveSNIExtension: %v", err)
	}
	checkRecordInvariants(t, out)
	sniPos, sniLen := func() (int, int) {
		_, p, l, _, err := ParseClientHello(out)
		if err != nil {
			t.Fatalf("re-parse: %v", err)
		}
		return p, l
	}()
	if sniPos != -1 || sniLen != 0 {
		t.Fatalf("SNI survived removal: pos=%d len=%d", sniPos, sniLen)
	}
	if len(out) >= len(ch) {
		t.Fatalf("record did not shrink: %d -> %d", len(ch), len(out))
	}
}

func TestAppendPaddingExtension_PadsAndFixesLengths(t *testing.T) {
	ch := buildClientHelloForTest("github.com")
	const n = 200
	out, err := AppendPaddingExtension(ch, n)
	if err != nil {
		t.Fatalf("AppendPaddingExtension: %v", err)
	}
	l := checkRecordInvariants(t, out)
	if len(out) != len(ch)+4+n {
		t.Fatalf("record grew to %d, want %d", len(out), len(ch)+4+n)
	}
	// Padding extension must be the final extension: type 0x0015, n zero bytes.
	tail := out[len(out)-4-n:]
	if !bytes.Equal(tail[:4], []byte{0x00, 0x15, byte(n >> 8), byte(n)}) {
		t.Fatalf("padding extension header = % X", tail[:4])
	}
	for _, b := range tail[4:] {
		if b != 0 {
			t.Fatal("padding bytes must be zero")
		}
	}
	// SNI must survive untouched.
	if !bytes.Equal(out[l.SniNameAt:l.SniNameAt+l.SniNameLen], []byte("github.com")) {
		t.Fatal("SNI changed by padding")
	}
}

func TestAppendPaddingExtension_CapsAtRecordLimit(t *testing.T) {
	ch := buildClientHelloForTest("github.com")
	out, err := AppendPaddingExtension(ch, 100000)
	if err != nil {
		t.Fatalf("AppendPaddingExtension: %v", err)
	}
	checkRecordInvariants(t, out)
	recordLen := int(binary.BigEndian.Uint16(out[3:5]))
	if recordLen > maxTLSRecordPayload {
		t.Fatalf("record payload %d exceeds TLS limit %d", recordLen, maxTLSRecordPayload)
	}
}

func TestAppendPaddingExtension_ZeroAndNegativeSizes(t *testing.T) {
	ch := buildClientHelloForTest("github.com")
	out, err := AppendPaddingExtension(ch, 0)
	if err != nil {
		t.Fatalf("AppendPaddingExtension(0): %v", err)
	}
	checkRecordInvariants(t, out)
	if len(out) != len(ch)+4 {
		t.Fatalf("zero padding must still add the 4-byte extension header, got %d -> %d", len(ch), len(out))
	}
	if _, err := AppendPaddingExtension(ch, -5); err != nil {
		t.Fatalf("negative padding must be treated as zero, got %v", err)
	}
}

func TestRebuiltRecordsStillFragmentCorrectly(t *testing.T) {
	ch := buildClientHelloForTest("gist.github.com")
	dotted, err := TrailingDotSNI(ch)
	if err != nil {
		t.Fatalf("TrailingDotSNI: %v", err)
	}
	recs := sendOverPipe(t, dotted, 4, 1, true, true)
	if len(recs) != 4 {
		t.Fatalf("got %d records, want 4", len(recs))
	}
	if !bytes.Equal(reassembled(recs), dotted[5:]) {
		t.Fatal("fragmented reassembly differs from rebuilt ClientHello")
	}
}
