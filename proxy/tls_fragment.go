package proxy

import (
	"net"

	"github.com/SnishaperTeam/snishaper-core/tlsfrag"
)

func (p *ProxyServer) handleTLSFragment(clientConn, upstreamConn net.Conn, host string, rule Rule) {
	cfg := p.effectiveFragmentConfig(rule)
	scope := "global"
	if rule.Frag != nil {
		scope = "rule"
	}
	p.tracef("[TLS-RF] Handling %s via upstream %s (%s scope, records=%d segments=%d interval=%dms modMinorVer=%t headerSplit=%t altRecordVer=%t)",
		host, rule.Upstream, scope, cfg.NumRecords, cfg.NumSegments, cfg.IntervalMillis(), cfg.ModMinorVerEnabled(), cfg.HeaderSplitEnabled(), cfg.AltRecordVerEnabled())

	record, err := tlsfrag.ReadInitialTLSRecord(clientConn)
	if err != nil {
		p.tracef("[TLS-RF] Failed to read initial TLS record for %s: %v", host, err)
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	record = p.rewriteClientHello(host, cfg, record)

	_, sniPos, sniLen, _, err := tlsfrag.ParseClientHello(record)
	if err != nil {
		p.tracef("[TLS-RF] Parse ClientHello failed for %s: %v", host, err)
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	if sniPos <= 0 || sniLen <= 0 {
		if _, err := upstreamConn.Write(record); err != nil {
			p.tracef("[TLS-RF] Initial passthrough write failed for %s: %v", host, err)
			clientConn.Close()
			upstreamConn.Close()
			return
		}
		p.tracef("[TLS-RF] No SNI in ClientHello for %s, forwarded directly", host)
		p.directTunnel(clientConn, upstreamConn)
		return
	}

	interval := cfg.Interval()

	err = tlsfrag.SendRecords(
		upstreamConn,
		record,
		sniPos,
		sniLen,
		cfg.NumRecords,
		cfg.NumSegments,
		cfg.OOBEnabled(),
		cfg.OOBExEnabled(),
		cfg.ModMinorVerEnabled(),
		cfg.HeaderSplitEnabled(),
		cfg.AltRecordVerEnabled(),
		interval,
	)
	if err != nil {
		p.tracef("[TLS-RF] Fragmented send failed for %s: %v", host, err)
		upstreamConn.Close()
		clientConn.Close()
		return
	}

	if cfg.NumRecords <= 1 {
		p.tracef("[TLS-RF] TCP-only fragmentation: %d segment(s), SNI moved to packet 2 for %s",
			cfg.NumSegments, host)
	} else {
		p.tracef("[TLS-RF] ClientHello split into %d TLS records / %d TCP segments for %s",
			cfg.NumRecords, cfg.NumSegments, host)
	}
	p.directTunnel(clientConn, upstreamConn)
}

func (p *ProxyServer) effectiveFragmentConfig(rule Rule) FragmentConfig {
	if rule.Frag != nil {
		return normalizeFragmentConfig(*rule.Frag)
	}
	return p.rules.GetFragmentConfig()
}

// rewriteClientHello applies the configured CircumVolve ClientHello rewrites
// (hidden SNI, trailing dot, RFC 7685 padding). Any failed rewrite falls back
// to the unmodified record so a malformed ClientHello never breaks the tunnel.
func (p *ProxyServer) rewriteClientHello(host string, cfg FragmentConfig, record []byte) []byte {
	if cfg.HideSNIEnabled() {
		out, err := tlsfrag.RemoveSNIExtension(record)
		if err != nil {
			p.tracef("[TLS-RF] HideSNI failed for %s: %v", host, err)
			return record
		}
		p.tracef("[TLS-RF] SNI hidden for %s", host)
		return out
	}
	if cfg.TrailingDotEnabled() {
		if out, err := tlsfrag.TrailingDotSNI(record); err == nil {
			record = out
			p.tracef("[TLS-RF] Trailing dot applied to SNI for %s", host)
		} else {
			p.tracef("[TLS-RF] TrailingDot failed for %s: %v", host, err)
		}
	}
	if n := cfg.PaddingLenInt(); n > 0 {
		if out, err := tlsfrag.AppendPaddingExtension(record, n); err == nil {
			record = out
			p.tracef("[TLS-RF] RFC 7685 padding of %d bytes applied for %s", n, host)
		} else {
			p.tracef("[TLS-RF] Padding failed for %s: %v", host, err)
		}
	}
	return record
}
