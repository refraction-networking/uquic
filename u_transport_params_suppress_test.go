package quic

import (
	"slices"
	"testing"
	"time"

	"github.com/refraction-networking/clienthellod"
	tls "github.com/refraction-networking/utls"
)

const (
	disableActiveMigrationID  uint64 = 0x0c
	activeConnectionIDLimitID uint64 = 0x0e
	maxDatagramFrameSizeID    uint64 = 0x20
)

// wireTransportParameterIDs dials with the spec, reassembles the ClientHello out of the
// Initial flight exactly as a QUIC fingerprinter does, and returns the sorted transport
// parameter IDs actually observed in the quic_transport_parameters extension.
func wireTransportParameterIDs(t *testing.T, spec *QUICSpec) []uint64 {
	t.Helper()

	// GatherClientInitials leaves the deadline at the zero time, i.e. already expired.
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

	if gci.TransportParameters == nil {
		t.Fatal("no quic_transport_parameters extension in the reassembled ClientHello")
	}
	if err := gci.TransportParameters.ParseError(); err != nil {
		t.Fatalf("parsing the transport parameters: %v", err)
	}
	return gci.TransportParameters.QTPIDs
}

// specTransportParameterIDs returns the sorted, deduplicated canonical IDs the spec's
// QUICTransportParametersExtension declares — GREASE IDs folded to QTPGrease, matching
// how fingerprinters bucket them. Calling ID() here also pins each GREASE parameter's
// random ID, so a later dial puts that same value on the wire.
func specTransportParameterIDs(t *testing.T, spec *QUICSpec) []uint64 {
	t.Helper()

	ext := specQTPExtension(t, spec)
	ids := make([]uint64, 0, len(ext.TransportParameters))
	for _, tp := range ext.TransportParameters {
		id := tp.ID()
		if IsGREASEQTPID(id) {
			id = QTPGrease
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	return ids
}

func specQTPExtension(t *testing.T, spec *QUICSpec) *tls.QUICTransportParametersExtension {
	t.Helper()

	for _, ext := range spec.ClientHelloSpec.Extensions {
		if qtp, ok := ext.(*tls.QUICTransportParametersExtension); ok {
			return qtp
		}
	}
	t.Fatal("spec has no QUICTransportParametersExtension")
	return nil
}

// TestWireTransportParameterIDsMatchSpec pins the invariant that the on-wire transport
// parameter set is exactly what the spec declares — uQUIC adds nothing of its own. In
// particular neither disable_active_migration (12) nor active_connection_id_limit (14)
// is injected: quic-go's own TransportParameters.Marshal, which would emit those, is
// never reached for a spec'd connection (u_crypto_setup.go leaves SetTransportParameters
// commented out; uTLS serializes the extension's parameter list directly).
func TestWireTransportParameterIDsMatchSpec(t *testing.T) {
	for _, id := range []QUICID{QUICChrome_146_IPv4, QUICChrome_115_IPv4, QUICFirefox_116} {
		t.Run(id.Client+"_"+id.Version, func(t *testing.T) {
			spec, err := QUICID2Spec(id)
			if err != nil {
				t.Fatal(err)
			}

			want := specTransportParameterIDs(t, &spec)
			got := wireTransportParameterIDs(t, &spec)
			if !slices.Equal(got, want) {
				t.Errorf("wire transport parameter IDs = %v, want %v", got, want)
			}
			// Spelled out separately from the equality above, because these two are the
			// ones quic-go's own Marshal would add: Firefox's spec declares both, Chrome's
			// declares neither, and each must get exactly what it asked for.
			for _, id := range []uint64{disableActiveMigrationID, activeConnectionIDLimitID} {
				if slices.Contains(got, id) != slices.Contains(want, id) {
					t.Errorf("transport parameter %d: on wire = %v, declared by spec = %v",
						id, slices.Contains(got, id), slices.Contains(want, id))
				}
			}
		})
	}
}

// TestSuppressTransportParametersOnWire covers the end-to-end effect of
// QUICSpec.SuppressTransportParameters, including QTPGrease matching whichever GREASE ID
// the parameter happened to draw.
func TestSuppressTransportParametersOnWire(t *testing.T) {
	spec, err := QUICID2Spec(QUICChrome_146_IPv4)
	if err != nil {
		t.Fatal(err)
	}
	declared := specTransportParameterIDs(t, &spec)
	for _, id := range []uint64{QTPGrease, maxDatagramFrameSizeID} {
		if !slices.Contains(declared, id) {
			t.Fatalf("precondition: Chrome 146 spec should declare parameter %d, has %v", id, declared)
		}
	}

	spec.SuppressTransportParameters = []uint64{QTPGrease, maxDatagramFrameSizeID}
	want := slices.DeleteFunc(slices.Clone(declared), func(id uint64) bool {
		return id == QTPGrease || id == maxDatagramFrameSizeID
	})

	got := wireTransportParameterIDs(t, &spec)
	if !slices.Equal(got, want) {
		t.Errorf("wire transport parameter IDs = %v, want %v", got, want)
	}
}

// TestSuppressQUICTransportParameters covers the filter itself: exact-ID matching,
// QTPGrease standing in for every GREASE ID, and leaving the list alone when nothing is
// suppressed.
func TestSuppressQUICTransportParameters(t *testing.T) {
	// A GREASE parameter whose ID is not the canonical 27, to prove QTPGrease does not
	// just compare equal.
	greaseID := uint64(27 + 31*5)

	newExt := func() *tls.QUICTransportParametersExtension {
		return &tls.QUICTransportParametersExtension{
			TransportParameters: tls.TransportParameters{
				tls.MaxIdleTimeout(30000),
				&tls.GREASETransportParameter{IdOverride: greaseID, Length: 4},
				tls.MaxDatagramFrameSize(65536),
				tls.InitialMaxData(15728640),
			},
		}
	}

	idsOf := func(ext *tls.QUICTransportParametersExtension) []uint64 {
		ids := make([]uint64, 0, len(ext.TransportParameters))
		for _, tp := range ext.TransportParameters {
			ids = append(ids, tp.ID())
		}
		return ids
	}

	for _, tc := range []struct {
		name     string
		suppress []uint64
		want     []uint64
	}{
		{name: "nothing", suppress: nil, want: []uint64{1, greaseID, 0x20, 4}},
		{name: "exact id", suppress: []uint64{0x20}, want: []uint64{1, greaseID, 4}},
		{name: "grease by canonical id", suppress: []uint64{QTPGrease}, want: []uint64{1, 0x20, 4}},
		{name: "several", suppress: []uint64{QTPGrease, 1, 4}, want: []uint64{0x20}},
		{name: "absent id", suppress: []uint64{0xdead}, want: []uint64{1, greaseID, 0x20, 4}},
		{name: "everything", suppress: []uint64{QTPGrease, 1, 4, 0x20}, want: []uint64{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ext := newExt()
			SuppressQUICTransportParameters(ext, tc.suppress)
			if got := idsOf(ext); !slices.Equal(got, tc.want) {
				t.Errorf("remaining parameter IDs = %v, want %v", got, tc.want)
			}
			// Applying the same suppression again must not remove anything further.
			SuppressQUICTransportParameters(ext, tc.suppress)
			if got := idsOf(ext); !slices.Equal(got, tc.want) {
				t.Errorf("suppression is not idempotent: %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsGREASEQTPID(t *testing.T) {
	for _, tc := range []struct {
		id   uint64
		want bool
	}{
		{id: 27, want: true},
		{id: 58, want: true}, // 27 + 31
		{id: 27 + 31*5, want: true},
		{id: 0, want: false},
		{id: 1, want: false},
		{id: 26, want: false},
		{id: 28, want: false},
		{id: 0x20, want: false},
	} {
		if got := IsGREASEQTPID(tc.id); got != tc.want {
			t.Errorf("IsGREASEQTPID(%d) = %v, want %v", tc.id, got, tc.want)
		}
	}
}

// TestVariableLengthGREASEQTPHonorsMaxLen covers the maxLen argument, which used to be
// ignored in favour of a hardcoded 0x10 — so a spec asking for a short GREASE parameter
// silently got up to 15 bytes, changing the quic_transport_parameters extension length.
func TestVariableLengthGREASEQTPHonorsMaxLen(t *testing.T) {
	for _, maxLen := range []int{1, 2, 5, 11, 0x10} {
		seen := make(map[int]bool)
		for i := 0; i < 500; i++ {
			got := len(VariableLengthGREASEQTP(maxLen).Value())
			if got >= maxLen {
				t.Fatalf("VariableLengthGREASEQTP(%d) produced a %d-byte value", maxLen, got)
			}
			seen[got] = true
		}
		// [0, maxLen) should be covered; 500 draws over at most 16 values makes a miss
		// astronomically unlikely.
		for want := 0; want < maxLen; want++ {
			if !seen[want] {
				t.Errorf("VariableLengthGREASEQTP(%d) never produced a %d-byte value", maxLen, want)
			}
		}
	}

	// Degenerate bounds must not panic (crypto/rand.Int panics on a non-positive max).
	for _, maxLen := range []int{-1, 0, 1} {
		if got := len(VariableLengthGREASEQTP(maxLen).Value()); got != 0 {
			t.Errorf("VariableLengthGREASEQTP(%d) produced a %d-byte value, want 0", maxLen, got)
		}
	}
}
