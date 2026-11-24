package quicrewrite

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestDeriveClientInitialKeys checks key derivation against the RFC 9001
// appendix A.1 test vector (DCID 8394c8f03e515708). The raw key is hidden
// behind the AEAD interface; the byte-exact packet test below plus the IV
// here prove the derivation matches the vector.
func TestDeriveClientInitialKeys(t *testing.T) {
	dcid := mustHex(t, "8394c8f03e515708")
	keys, err := deriveClientInitialKeys(dcid)
	if err != nil {
		t.Fatal(err)
	}
	if want := mustHex(t, "fa044b2f42a3fd3b46fb255c"); !bytes.Equal(keys.iv, want) {
		t.Fatalf("unexpected IV: %x, want %x", keys.iv, want)
	}
	// Client/server secrets must differ; seal with client keys must open
	// with the same client keys (sanity roundtrip).
	sealed := keys.seal([]byte("hello"), []byte("hdr"), 7)
	opened, err := keys.open(sealed, []byte("hdr"), 7)
	if err != nil || !bytes.Equal(opened, []byte("hello")) {
		t.Fatalf("seal/open roundtrip failed: %v %q", err, opened)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// The RFC 9001 appendix A.1 client Initial fixture: header (PN=2), plaintext
// CRYPTO frame carrying a 241-byte ClientHello with SNI example.com, and the
// expected 1200-byte protected packet.
const (
	vectorHdrHex      = "c300000001088394c8f03e5157080000449e00000002"
	vectorDataHex     = "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff"
	vectorPacketHex   = "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934"
)

// buildVectorInitial assembles the RFC 9001 A.1 packet with our own code:
// serialize the header, seal the plaintext, protect the header. The
// byte-exact match with vectorPacketHex proves the whole seal path.
func buildVectorInitial(t *testing.T) []byte {
	t.Helper()
	full := mustHex(t, vectorPacketHex)
	data := mustHex(t, vectorDataHex)
	plaintext := append(append([]byte{}, data...), make([]byte, 1162-len(data))...)

	h, err := parseInitialHeader(full)
	if err != nil {
		t.Fatalf("parse vector header: %v", err)
	}
	if h.pnLen != 4 || h.pnOffset != 18 || h.payloadStart != 22 || h.packetEnd != 1200 {
		t.Fatalf("unexpected header layout: %+v", h)
	}
	keys, err := deriveClientInitialKeys(h.dcid)
	if err != nil {
		t.Fatal(err)
	}
	sealed := keys.seal(plaintext, mustHex(t, vectorHdrHex), 2)
	packet := append(append([]byte{}, mustHex(t, vectorHdrHex)...), sealed...)
	keys.applyHeaderProtection(packet, h.pnOffset, h.pnLen, packet[h.pnOffset+4:h.pnOffset+4+sampleLen])
	return packet
}

func TestSealMatchesRFCVector(t *testing.T) {
	packet := buildVectorInitial(t)
	want := mustHex(t, vectorPacketHex)
	if !bytes.Equal(packet, want) {
		t.Fatalf("sealed packet does not match RFC 9001 A.1 vector (got %d bytes, want %d)", len(packet), len(want))
	}
}

// openInitial reverses RewriteInitial for test assertions: unprotect, open,
// reassemble CRYPTO. Returns the decrypted plaintext.
func openInitial(t *testing.T, datagram []byte) []byte {
	t.Helper()
	h, err := parseInitialHeader(datagram)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	keys, err := deriveClientInitialKeys(h.dcid)
	if err != nil {
		t.Fatal(err)
	}
	hdr, pn := keys.unprotect(datagram, &h)
	plaintext, err := keys.open(datagram[h.payloadStart:h.packetEnd], hdr, pn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return plaintext
}

// cryptoFrames collects (offset, data) pairs from a decrypted Initial plaintext.
func cryptoFrames(t *testing.T, plaintext []byte) []struct {
	offset uint64
	data   []byte
} {
	t.Helper()
	var frames []struct {
		offset uint64
		data   []byte
	}
	pos := 0
	for pos < len(plaintext) {
		switch plaintext[pos] {
		case 0x00, 0x01:
			pos++
		case 0x02: // ACK
			frames = append(frames, struct {
				offset uint64
				data   []byte
			}{^uint64(0), plaintext[pos : pos+5]})
			pos += 5
		case 0x06:
			pos++
			off, p, err := readVarint(plaintext, pos)
			if err != nil {
				t.Fatalf("varint: %v", err)
			}
			n, p2, err := readVarint(plaintext, p)
			if err != nil {
				t.Fatalf("varint: %v", err)
			}
			frames = append(frames, struct {
				offset uint64
				data   []byte
			}{off, plaintext[p2 : p2+int(n)]})
			pos = p2 + int(n)
		default:
			t.Fatalf("unexpected frame type %#x at %d", plaintext[pos], pos)
		}
	}
	return frames
}

var allStrategies = Strategies{
	ReservedBits:   true,
	PrependACK:     true,
	DecoyCrypto:    true,
	FragmentCrypto: true,
	DoubleHello:    true,
	PunycodeSNI:    true,
}

func TestRewriteInitialEachStrategy(t *testing.T) {
	vector := mustHex(t, vectorPacketHex)

	cases := []struct {
		name string
		s    Strategies
	}{
		{"reserved_bits", Strategies{ReservedBits: true}},
		{"prepend_ack", Strategies{PrependACK: true}},
		{"decoy_crypto", Strategies{DecoyCrypto: true}},
		{"fragment_crypto", Strategies{FragmentCrypto: true}},
		{"double_hello", Strategies{DoubleHello: true}},
		{"punycode_sni", Strategies{PunycodeSNI: true}},
		{"all", allStrategies},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := append([]byte(nil), vector...)
			orig := append([]byte(nil), vector...)

			out, ok := RewriteInitial(input, tc.s)
			if !ok {
				t.Fatal("expected rewrite")
			}
			if !bytes.Equal(input, orig) {
				t.Fatal("input datagram was modified")
			}
			if len(out) < 1200 {
				t.Fatalf("rewritten datagram shrank below 1200: %d", len(out))
			}
			plaintext := openInitial(t, out)

			switch tc.name {
			case "reserved_bits":
				h, _ := parseInitialHeader(out)
				keys, _ := deriveClientInitialKeys(h.dcid)
				hdr, _ := keys.unprotect(out, &h)
				if hdr[0]&0x0c != 0x0c {
					t.Fatalf("reserved bits not set after unprotection: %#x", hdr[0])
				}
			case "prepend_ack":
				if !bytes.HasPrefix(plaintext, ackInitial) {
					t.Fatalf("plaintext does not start with ACK: %x", plaintext[:8])
				}
			case "decoy_crypto":
				frames := cryptoFrames(t, plaintext)
				if len(frames) != 2 || frames[0].offset != decoyCryptoOffset || len(frames[0].data) != decoyCryptoLen {
					t.Fatalf("unexpected decoy frame: %+v", frames[0])
				}
				if frames[1].offset != 0 {
					t.Fatalf("real CRYPTO not at offset 0: %d", frames[1].offset)
				}
			case "fragment_crypto":
				frames := cryptoFrames(t, plaintext)
				if len(frames) != 2 || frames[0].offset != 0 || frames[1].offset != uint64(len(frames[0].data)) {
					t.Fatalf("expected contiguous split CRYPTO frames: %+v", frames)
				}
				if !bytes.Equal(append(frames[0].data, frames[1].data...), mustHex(t, vectorDataHex)[4:]) {
					t.Fatal("reassembled ClientHello differs from vector")
				}
			case "double_hello":
				frames := cryptoFrames(t, plaintext)
				if len(frames) != 2 || frames[0].offset != 0 || frames[1].offset != uint64(len(frames[0].data)) {
					t.Fatalf("expected two CRYPTO frames: %+v", frames)
				}
				if n := sniName(frames[0].data); n != nil {
					t.Fatalf("first CH still has SNI: %q", n)
				}
				if n := sniName(frames[1].data); string(n) != "example.com" {
					t.Fatalf("second CH SNI = %q, want example.com", n)
				}
			case "punycode_sni":
				frames := cryptoFrames(t, plaintext)
				if len(frames) != 1 || frames[0].offset != 0 {
					t.Fatalf("expected single CRYPTO frame: %+v", frames)
				}
				if n := sniName(frames[0].data); string(n) != "xn--6578616d706c652e636f6d" {
					t.Fatalf("punycode SNI = %q", n)
				}
			case "all":
				frames := cryptoFrames(t, plaintext)
				if len(frames) != 4 { // decoy + CH-without-SNI + minimal CH + padding
					t.Fatalf("expected 4 frames, got %d: %+v", len(frames), frames)
				}
			}
		})
	}
}

func TestRewriteInitialPassthrough(t *testing.T) {
	vector := mustHex(t, vectorPacketHex)

	if out, ok := RewriteInitial(vector, Strategies{}); ok || out != nil {
		t.Fatal("no strategies must pass through")
	}
	if out, ok := RewriteInitial(vector[:40], Strategies{ReservedBits: true}); ok || out != nil {
		t.Fatal("truncated datagram must pass through")
	}
	short := append([]byte{0x40, 0x00, 0x00, 0x00, 0x01}, make([]byte, 1195)...)
	if out, ok := RewriteInitial(short, Strategies{ReservedBits: true}); ok || out != nil {
		t.Fatal("short header must pass through")
	}
	v2 := append([]byte(nil), vector...)
	v2[1], v2[2], v2[3], v2[4] = 0x6b, 0x33, 0x43, 0xcf // QUIC v2
	if out, ok := RewriteInitial(v2, Strategies{ReservedBits: true}); ok || out != nil {
		t.Fatal("non-v1 version must pass through")
	}
	// Coalesced trailing bytes must survive the rewrite untouched.
	tail := []byte{0xde, 0xad, 0xbe, 0xef}
	withTail := append(append([]byte(nil), vector...), tail...)
	out, ok := RewriteInitial(withTail, Strategies{ReservedBits: true})
	if !ok {
		t.Fatal("expected rewrite")
	}
	if !bytes.HasSuffix(out, tail) {
		t.Fatal("coalesced tail lost")
	}
}

// Fuzz smoke: arbitrary input must never panic and never report a rewrite
// that shrinks the datagram.
func FuzzRewriteInitial(f *testing.F) {
	seed, _ := hex.DecodeString(vectorPacketHex)
	f.Add(seed)
	f.Add([]byte{0xc0, 0x00, 0x00, 0x00, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		out, ok := RewriteInitial(data, allStrategies)
		if !ok {
			return
		}
		if len(out) < len(data) {
			t.Fatalf("output shrank: %d < %d", len(out), len(data))
		}
	})
}
