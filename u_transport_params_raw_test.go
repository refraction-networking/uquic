package quic

import (
	"encoding/binary"
	"slices"
	"testing"
	"time"

	"github.com/refraction-networking/clienthellod"
	"github.com/refraction-networking/uquic/quicvarint"
	tls "github.com/refraction-networking/utls"
)

const quicTransportParametersExtensionID = 57

// rawWireTransportParameterIDs dials with the spec and returns the transport parameter
// IDs from the ClientHello's quic_transport_parameters extension exactly as they appear
// on the wire: in order, unsorted, and with GREASE IDs left at their real values.
//
// wireTransportParameterIDs (u_transport_params_suppress_test.go) goes through
// clienthellod, which sorts and folds every GREASE ID to 27 the way a fingerprinter does.
// That is the right view for fingerprint comparisons but useless for checking which
// literal ID reached the wire, or in what order.
func rawWireTransportParameterIDs(t *testing.T, spec *QUICSpec) []uint64 {
	t.Helper()

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

	ext := clientHelloExtension(t, gci.ClientHello.Raw(), quicTransportParametersExtensionID)
	var ids []uint64
	for len(ext) > 0 {
		id, n, err := quicvarint.Parse(ext)
		if err != nil {
			t.Fatalf("parsing a transport parameter ID: %v", err)
		}
		ext = ext[n:]
		valLen, n, err := quicvarint.Parse(ext)
		if err != nil {
			t.Fatalf("parsing the length of transport parameter %d: %v", id, err)
		}
		ext = ext[n:]
		if uint64(len(ext)) < valLen {
			t.Fatalf("transport parameter %d claims %d value bytes, only %d left", id, valLen, len(ext))
		}
		ext = ext[valLen:]
		ids = append(ids, id)
	}
	return ids
}

// clientHelloExtension returns the body of the given extension in a raw ClientHello
// handshake message.
func clientHelloExtension(t *testing.T, ch []byte, want uint16) []byte {
	t.Helper()

	take := func(n int) []byte {
		if len(ch) < n {
			t.Fatalf("ClientHello truncated: wanted %d bytes, have %d", n, len(ch))
		}
		b := ch[:n]
		ch = ch[n:]
		return b
	}

	if len(ch) > 0 && ch[0] == 0x01 { // handshake type client_hello, plus a uint24 length
		take(4)
	}
	take(2 + 32)                                // legacy_version, random
	take(int(take(1)[0]))                       // legacy_session_id
	take(int(binary.BigEndian.Uint16(take(2)))) // cipher_suites
	take(int(take(1)[0]))                       // legacy_compression_methods

	exts := take(int(binary.BigEndian.Uint16(take(2))))
	for len(exts) >= 4 {
		id := binary.BigEndian.Uint16(exts[:2])
		size := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if len(exts) < size {
			t.Fatalf("extension %d claims %d bytes, only %d left", id, size, len(exts))
		}
		if id == want {
			return exts[:size]
		}
		exts = exts[size:]
	}
	t.Fatalf("ClientHello has no extension %d", want)
	return nil
}

// TestFakeQUICTransportParameterReachesWireVerbatim pins that uTLS serializes a
// FakeQUICTransportParameter's ID unchanged, including IDs that satisfy the GREASE
// pattern 31*N+27 — 0x1b (N=0) most of all. Nothing in the transport parameter
// serializer filters, rewrites, or randomizes IDs: tls.TransportParameters.Marshal
// appends ID(), len(Value()), Value() for every entry, and FakeQUICTransportParameter.ID
// returns its Id field as-is (it only rejects 0).
func TestFakeQUICTransportParameterReachesWireVerbatim(t *testing.T) {
	// Every ID here is a GREASE value (31*N+27), i.e. exactly the pattern a GREASE filter
	// would strip if one existed.
	greaseShaped := []uint64{0x1b, 0x1b + 31, 0x1b + 31*2}

	spec, err := QUICID2Spec(QUICChrome_146_IPv4)
	if err != nil {
		t.Fatal(err)
	}
	ext := specQTPExtension(t, &spec)
	// Drop the parrot's own GREASE parameter so the only GREASE-shaped IDs on the wire
	// are the literal ones added below.
	SuppressQUICTransportParameters(ext, []uint64{QTPGrease})
	for _, id := range greaseShaped {
		ext.TransportParameters = append(ext.TransportParameters,
			&tls.FakeQUICTransportParameter{Id: id, Val: []byte{0xaa, 0xbb}})
	}

	got := rawWireTransportParameterIDs(t, &spec)
	for _, id := range greaseShaped {
		if !slices.Contains(got, id) {
			t.Errorf("transport parameter 0x%x is missing from the wire; got %v", id, got)
		}
	}
}

// TestVariableLengthGREASEQTPReachesWire is the counterpart: a real GREASE parameter also
// reaches the wire, with a GREASE-patterned ID drawn at random rather than a fixed 0x1b.
func TestVariableLengthGREASEQTPReachesWire(t *testing.T) {
	spec, err := QUICID2Spec(QUICChrome_146_IPv4)
	if err != nil {
		t.Fatal(err)
	}
	ext := specQTPExtension(t, &spec)
	SuppressQUICTransportParameters(ext, []uint64{QTPGrease})
	grease := VariableLengthGREASEQTP(0x10)
	ext.TransportParameters = append(ext.TransportParameters, grease)

	wantID := grease.ID() // pins the random draw; the dial below sends this same ID
	if !IsGREASEQTPID(wantID) {
		t.Fatalf("VariableLengthGREASEQTP drew a non-GREASE ID %d", wantID)
	}

	got := rawWireTransportParameterIDs(t, &spec)
	if !slices.Contains(got, wantID) {
		t.Errorf("GREASE transport parameter %d is missing from the wire; got %v", wantID, got)
	}
}

// TestSpecTransportParameterIDs covers QUICSpec.TransportParameterIDs, including the
// duplicate-27 collision it exists to expose: a spec carrying both an explicit
// FakeQUICTransportParameter{Id: 0x1b} and a GREASE parameter emits two distinct wire
// IDs, but a fingerprinter canonicalizes both to 27.
func TestSpecTransportParameterIDs(t *testing.T) {
	newSpec := func(tps ...tls.TransportParameter) *QUICSpec {
		return &QUICSpec{ClientHelloSpec: &tls.ClientHelloSpec{
			Extensions: []tls.TLSExtension{
				&tls.SNIExtension{},
				&tls.QUICTransportParametersExtension{TransportParameters: tps},
			},
		}}
	}

	t.Run("canonicalizes and sorts", func(t *testing.T) {
		spec := newSpec(
			tls.MaxDatagramFrameSize(65536), // 0x20
			&tls.GREASETransportParameter{IdOverride: 27 + 31*7, Length: 4},
			tls.MaxIdleTimeout(30000), // 0x01
		)
		want := []uint64{1, QTPGrease, 0x20}
		if got := spec.TransportParameterIDs(); !slices.Equal(got, want) {
			t.Errorf("TransportParameterIDs() = %v, want %v", got, want)
		}
	})

	t.Run("exposes duplicate canonical ids", func(t *testing.T) {
		spec := newSpec(
			tls.MaxIdleTimeout(30000),
			&tls.FakeQUICTransportParameter{Id: 0x1b, Val: []byte{0x00}},
			&tls.GREASETransportParameter{IdOverride: 27 + 31*7, Length: 4},
		)
		want := []uint64{1, QTPGrease, QTPGrease}
		if got := spec.TransportParameterIDs(); !slices.Equal(got, want) {
			t.Errorf("TransportParameterIDs() = %v, want %v", got, want)
		}
	})

	t.Run("applies suppression", func(t *testing.T) {
		spec := newSpec(
			tls.MaxIdleTimeout(30000),
			&tls.FakeQUICTransportParameter{Id: 0x1b, Val: []byte{0x00}},
			&tls.GREASETransportParameter{IdOverride: 27 + 31*7, Length: 4},
		)
		spec.SuppressTransportParameters = []uint64{QTPGrease}
		if got := spec.TransportParameterIDs(); !slices.Equal(got, []uint64{1}) {
			t.Errorf("TransportParameterIDs() = %v, want [1]", got)
		}
	})

	t.Run("no transport parameters extension", func(t *testing.T) {
		spec := &QUICSpec{ClientHelloSpec: &tls.ClientHelloSpec{
			Extensions: []tls.TLSExtension{&tls.SNIExtension{}},
		}}
		if got := spec.TransportParameterIDs(); got != nil {
			t.Errorf("TransportParameterIDs() = %v, want nil", got)
		}
		if got := (&QUICSpec{}).TransportParameterIDs(); got != nil {
			t.Errorf("TransportParameterIDs() on an empty spec = %v, want nil", got)
		}
	})
}

// TestSpecTransportParameterIDsMatchWire ties the two together: what the spec predicts is
// what a fingerprinter reads off the wire.
func TestSpecTransportParameterIDsMatchWire(t *testing.T) {
	for _, id := range []QUICID{QUICChrome_146_IPv4, QUICFirefox_116} {
		t.Run(id.Client+"_"+id.Version, func(t *testing.T) {
			spec, err := QUICID2Spec(id)
			if err != nil {
				t.Fatal(err)
			}
			want := spec.TransportParameterIDs()
			if got := wireTransportParameterIDs(t, &spec); !slices.Equal(got, want) {
				t.Errorf("wire IDs = %v, TransportParameterIDs() predicted %v", got, want)
			}
		})
	}
}
