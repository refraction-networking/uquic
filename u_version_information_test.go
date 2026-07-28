package quic

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/refraction-networking/clienthellod"
	"github.com/refraction-networking/uquic/quicvarint"
	tls "github.com/refraction-networking/utls"
)

// wireVersionInformation dials with the spec and returns the chosen version followed by
// the available versions, read out of the version_information transport parameter as it
// appears on the wire. It accepts either the RFC-assigned ID (0x11) or the legacy draft
// ID (0xff73db), since parrots differ on which one they send.
func wireVersionInformation(t *testing.T, spec *QUICSpec) []uint32 {
	t.Helper()

	const (
		versionInformationID       uint64 = 0x11
		versionInformationLegacyID uint64 = 0xff73db
	)

	gci := clienthellod.GatherClientInitialsWithDeadline(time.Now().Add(time.Minute))
	dialAndCaptureDatagrams(t, spec, func(datagram []byte) bool {
		ci, err := clienthellod.UnmarshalQUICClientInitialPacket(datagram)
		if err != nil {
			t.Fatalf("parsing a client Initial: %v", err)
		}
		if err := gci.AddPacket(ci); err != nil {
			t.Fatalf("gathering client Initials: %v", err)
		}
		return !gci.Completed()
	})
	if gci.ClientHello == nil {
		t.Fatal("no ClientHello reassembled from the Initial flight")
	}

	body := clientHelloExtension(t, gci.ClientHello.Raw(), quicTransportParametersExtensionID)
	for len(body) > 0 {
		id, n, err := quicvarint.Parse(body)
		if err != nil {
			t.Fatalf("parsing a transport parameter ID: %v", err)
		}
		body = body[n:]
		valLen, n, err := quicvarint.Parse(body)
		if err != nil {
			t.Fatalf("parsing the length of transport parameter %d: %v", id, err)
		}
		body = body[n:]
		if uint64(len(body)) < valLen {
			t.Fatalf("transport parameter %d claims %d value bytes, only %d left", id, valLen, len(body))
		}
		val := body[:valLen]
		body = body[valLen:]

		if id != versionInformationID && id != versionInformationLegacyID {
			continue
		}
		if valLen%4 != 0 {
			t.Fatalf("version_information is %d bytes, want a multiple of 4", valLen)
		}
		versions := make([]uint32, 0, valLen/4)
		for i := 0; i < len(val); i += 4 {
			versions = append(versions, binary.BigEndian.Uint32(val[i:i+4]))
		}
		return versions
	}
	t.Fatal("no version_information transport parameter on the wire")
	return nil
}

// isReservedQUICVersion reports whether v follows the reserved "GREASE" version pattern
// 0x?a?a?a?a from RFC 9000 §15.
func isReservedQUICVersion(v uint32) bool {
	return v&0x0f0f0f0f == 0x0a0a0a0a
}

// requireFixedGREASEVersions skips the caller unless the linked uTLS generates well-formed
// GREASE versions. The fix lives in uTLS (GetGREASEVersion must mask the low nibbles
// before setting them, not just OR them), and this module resolves uTLS from the module
// cache — so until go.mod points at a uTLS that carries the fix, there is nothing here for
// uQUIC to test. 64 draws makes a false skip effectively impossible: a broken uTLS passes
// any single draw only 1 time in 256.
func requireFixedGREASEVersions(t *testing.T) {
	t.Helper()

	var vi tls.VersionInformation
	for i := 0; i < 64; i++ {
		if !isReservedQUICVersion(vi.GetGREASEVersion()) {
			t.Skipf("linked uTLS generates malformed GREASE versions (e.g. %#08x); "+
				"update the utls dependency to one that masks the low nibbles in GetGREASEVersion",
				vi.GetGREASEVersion())
		}
	}
}

// TestWireVersionInformationGREASE checks the version_information transport parameter on
// the wire: every version a parrot advertises must be either a real QUIC version or a
// well-formed 0x?a?a?a?a reserved version. uTLS's GetGREASEVersion used to OR its random
// bits with 0x0a0a0a0a instead of masking the low nibbles first, so 255 connections out
// of 256 advertised something like 0xeafa8eff — not a GREASE value, and not something any
// real browser sends.
//
// The parrots pass tls.VERSION_GREASE in AvailableVersions as a sentinel, and uTLS swaps
// in a freshly drawn version at serialization time, so a fresh spec per dial gives a
// fresh version. Several dials are made to make a lucky draw unlikely to hide a
// regression: under the old behaviour each dial had only a 1-in-256 chance of passing.
func TestWireVersionInformationGREASE(t *testing.T) {
	requireFixedGREASEVersions(t)

	realVersions := map[uint32]bool{
		uint32(tls.VERSION_1): true,
		uint32(tls.VERSION_2): true,
	}

	for _, id := range []QUICID{QUICChrome_146_IPv4, QUICChrome_115_IPv4, QUICFirefox_116} {
		t.Run(id.Client+"_"+id.Version, func(t *testing.T) {
			var sawGREASE bool
			greaseValues := make(map[uint32]bool)

			for i := 0; i < 5; i++ {
				spec, err := QUICID2Spec(id) // a fresh spec redraws the GREASE version
				if err != nil {
					t.Fatal(err)
				}
				versions := wireVersionInformation(t, &spec)
				if len(versions) < 2 {
					t.Fatalf("version_information carried %d versions, want a chosen version plus at least one available", len(versions))
				}
				if chosen := versions[0]; !realVersions[chosen] {
					t.Errorf("chosen version = %#08x, want a real QUIC version", chosen)
				}
				for _, v := range versions[1:] {
					if realVersions[v] {
						continue
					}
					if !isReservedQUICVersion(v) {
						t.Errorf("advertised version %#08x is neither a real QUIC version nor a 0x?a?a?a?a reserved version", v)
						continue
					}
					sawGREASE = true
					greaseValues[v] = true
				}
			}

			if !sawGREASE {
				t.Fatal("no GREASE version advertised; this parrot no longer exercises the substitution path")
			}
			// A constant GREASE version across connections would itself be a fingerprint.
			if len(greaseValues) < 2 {
				t.Errorf("only %d distinct GREASE version(s) across 5 dials, want them redrawn per connection", len(greaseValues))
			}
		})
	}
}
