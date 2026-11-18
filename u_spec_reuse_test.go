package quic

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/refraction-networking/clienthellod"
	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/testdata"
	"github.com/refraction-networking/uquic/internal/wire"
	"github.com/refraction-networking/uquic/quicvarint"
	tls "github.com/refraction-networking/utls"
)

const initialSourceConnectionIDParameterID uint64 = 0x0f

// reusableFirefoxSpec returns the Firefox 116 parrot with transport parameter
// suppression and shuffling turned on, so a dial runs every rewrite uQUIC makes to the
// transport parameters. The parrot uses a 3-byte source connection ID and declares a
// zero-length initial_source_connection_id, which uQUIC fills in per connection. It
// also carries a GREASE parameter, whose ID and value are drawn lazily.
func reusableFirefoxSpec(t *testing.T) *QUICSpec {
	t.Helper()

	spec, err := QUICID2Spec(QUICFirefox_116)
	if err != nil {
		t.Fatal(err)
	}
	spec.RandomizeTransportParameters = true
	spec.SuppressTransportParameters = []uint64{maxDatagramFrameSizeID}

	if spec.InitialPacketSpec.SrcConnIDLength == 0 {
		t.Fatal("precondition: the spec must use a non-empty source connection ID")
	}
	var zeroLengthSCID, grease bool
	for _, tp := range specQTPExtension(t, &spec).TransportParameters {
		switch tp := tp.(type) {
		case tls.InitialSourceConnectionID:
			zeroLengthSCID = len(tp) == 0
		case *tls.GREASETransportParameter:
			grease = !tp.IsGREASEID(tp.IdOverride) && len(tp.ValueOverride) == 0
		}
	}
	if !zeroLengthSCID || !grease {
		t.Fatalf("precondition: want a zero-length initial_source_connection_id (%t) and an undrawn GREASE parameter (%t)", zeroLengthSCID, grease)
	}
	return &spec
}

// specSnapshot renders everything in spec that a dial could write to. Each extension
// is printed with %#v, which includes unexported fields such as a cached encoding.
// Transport parameters are printed one by one too, because inside the extension a
// pointer parameter (GREASE, version_information) shows only its address.
func specSnapshot(spec *QUICSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%#v\n%#v\n", *spec, *spec.ClientHelloSpec)
	for _, ext := range spec.ClientHelloSpec.Extensions {
		fmt.Fprintf(&b, "%#v\n", ext)
		if qtp, ok := ext.(*tls.QUICTransportParametersExtension); ok {
			for _, tp := range qtp.TransportParameters {
				fmt.Fprintf(&b, "\t%#v\n", tp)
			}
		}
	}
	return b.String()
}

// flightSCIDs reassembles the ClientHello from a client flight and returns the source
// connection ID in the header of the flight's first Initial packet, together with the
// initial_source_connection_id transport parameter in that ClientHello. Packets other
// than that connection's Initials are skipped. Feed datagrams in the order they were
// sent; add reports whether the ClientHello is still incomplete.
type flightSCIDs struct {
	t      *testing.T
	gci    *clienthellod.GatheredClientInitials
	header []byte
}

func newFlightSCIDs(t *testing.T) *flightSCIDs {
	return &flightSCIDs{t: t, gci: clienthellod.GatherClientInitialsWithDeadline(time.Now().Add(time.Minute))}
}

func (f *flightSCIDs) add(datagram []byte) (more bool) {
	f.t.Helper()

	if len(datagram) == 0 || !wire.IsLongHeaderPacket(datagram[0]) {
		return true
	}
	hdr, _, _, err := wire.ParsePacket(datagram)
	if err != nil || hdr.Type != protocol.PacketTypeInitial {
		return true
	}
	if f.header == nil {
		f.header = hdr.SrcConnectionID.Bytes()
	} else if !bytes.Equal(f.header, hdr.SrcConnectionID.Bytes()) {
		return true
	}
	ci, err := clienthellod.UnmarshalQUICClientInitialPacket(datagram)
	if err != nil {
		f.t.Fatalf("parsing a client Initial: %v", err)
	}
	if err := f.gci.AddPacket(ci); err != nil {
		f.t.Fatalf("gathering client Initials: %v", err)
	}
	return !f.gci.Completed()
}

func (f *flightSCIDs) result() (header, param []byte) {
	f.t.Helper()

	if !f.gci.Completed() || f.gci.ClientHello == nil {
		f.t.Fatal("no complete ClientHello in the client's Initial packets")
	}
	ext := clientHelloExtension(f.t, f.gci.ClientHello.Raw(), quicTransportParametersExtensionID)
	for len(ext) > 0 {
		id, n, err := quicvarint.Parse(ext)
		if err != nil {
			f.t.Fatalf("parsing a transport parameter ID: %v", err)
		}
		ext = ext[n:]
		valLen, n, err := quicvarint.Parse(ext)
		if err != nil || uint64(len(ext)-n) < valLen {
			f.t.Fatalf("transport parameter %d has a bad length", id)
		}
		ext = ext[n:]
		if id == initialSourceConnectionIDParameterID {
			return f.header, ext[:valLen]
		}
		ext = ext[valLen:]
	}
	f.t.Fatal("ClientHello carries no initial_source_connection_id")
	return nil, nil
}

// checkFlightSCIDs checks that a dial's ClientHello carries that dial's own source
// connection ID, and returns it.
func checkFlightSCIDs(t *testing.T, dial int, f *flightSCIDs, want int) []byte {
	t.Helper()

	header, param := f.result()
	if len(header) != want {
		t.Errorf("dial %d: source connection ID %x has length %d, want %d", dial, header, len(header), want)
	}
	if !bytes.Equal(param, header) {
		t.Errorf("dial %d: initial_source_connection_id = %x, but the Initial header's source connection ID is %x", dial, param, header)
	}
	return header
}

// recordingPacketConn records every datagram written through it. It hides the
// *net.UDPConn's OOB methods, so the transport sends everything through WriteTo.
type recordingPacketConn struct {
	net.PacketConn

	mu   sync.Mutex
	sent [][]byte
}

func (c *recordingPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.sent = append(c.sent, slices.Clone(b))
	c.mu.Unlock()
	return c.PacketConn.WriteTo(b, addr)
}

func (c *recordingPacketConn) datagrams() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.sent)
}

// TestUTransportDialsTwiceWithOneSpec dials one server twice through one UTransport and
// one QUICSpec, as http3.Transport does when it re-dials. uQUIC used to write the first
// connection's source connection ID into the spec's zero-length
// initial_source_connection_id. The second dial then sent that stale ID, and the server
// closed the connection with TRANSPORT_PARAMETER_ERROR.
//
// Both dials must complete, each must send its own source connection ID, and the spec
// must be left exactly as built. That includes the parts uTLS fills in per connection
// (key shares and others), so this test also needs a uTLS whose ApplyPreset leaves the
// caller's spec alone.
func TestUTransportDialsTwiceWithOneSpec(t *testing.T) {
	spec := reusableFirefoxSpec(t)
	before := specSnapshot(spec)

	serverTLS := testdata.GetTLSConfig()
	serverTLS.NextProtos = []string{"h3"}
	ln, err := ListenAddr("127.0.0.1:0", serverTLS, &Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			defer conn.CloseWithError(0, "")
		}
	}()

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	clientConn := &recordingPacketConn{PacketConn: udpConn}
	tr := &UTransport{Transport: &Transport{Conn: clientConn}, QUICSpec: spec}
	defer tr.Close()

	var scids [][]byte
	for dial := 1; dial <= 2; dial++ {
		start := len(clientConn.datagrams())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := tr.Dial(ctx, ln.Addr(), &tls.Config{ServerName: "localhost", InsecureSkipVerify: true}, &Config{})
		cancel()
		if err != nil {
			t.Fatalf("dial %d: %v", dial, err)
		}
		conn.CloseWithError(0, "")

		f := newFlightSCIDs(t)
		for _, d := range clientConn.datagrams()[start:] {
			if !f.add(d) {
				break
			}
		}
		scids = append(scids, checkFlightSCIDs(t, dial, f, spec.InitialPacketSpec.SrcConnIDLength))
	}
	if bytes.Equal(scids[0], scids[1]) {
		t.Errorf("both dials used source connection ID %x", scids[0])
	}

	if after := specSnapshot(spec); after != before {
		t.Errorf("dialing changed the spec\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestSpecReuseSendsEachConnectionsOwnSCID is the uQUIC half of the test above,
// independent of uTLS: it only captures each dial's Initial flight, so no handshake has
// to complete. Every dial from one spec must carry its own source connection ID in
// initial_source_connection_id, and the spec's transport parameters extension must be
// left as built.
func TestSpecReuseSendsEachConnectionsOwnSCID(t *testing.T) {
	spec := reusableFirefoxSpec(t)
	qtp := specQTPExtension(t, spec)
	before := fmt.Sprintf("%#v", *qtp)
	var beforeParams []string
	for _, tp := range qtp.TransportParameters {
		beforeParams = append(beforeParams, fmt.Sprintf("%#v", tp))
	}

	var scids [][]byte
	for dial := 1; dial <= 3; dial++ {
		f := newFlightSCIDs(t)
		dialAndCaptureDatagrams(t, spec, f.add)
		scids = append(scids, checkFlightSCIDs(t, dial, f, spec.InitialPacketSpec.SrcConnIDLength))
	}
	for i := 1; i < len(scids); i++ {
		if bytes.Equal(scids[i], scids[0]) {
			t.Errorf("dials 1 and %d used source connection ID %x", i+1, scids[0])
		}
	}

	if qtp != specQTPExtension(t, spec) {
		t.Error("dialing replaced the spec's transport parameters extension")
	}
	if after := fmt.Sprintf("%#v", *qtp); after != before {
		t.Errorf("dialing changed the spec's transport parameters extension\nbefore: %s\nafter:  %s", before, after)
	}
	var afterParams []string
	for _, tp := range qtp.TransportParameters {
		afterParams = append(afterParams, fmt.Sprintf("%#v", tp))
	}
	if !slices.Equal(afterParams, beforeParams) {
		t.Errorf("dialing changed the spec's transport parameters\nbefore: %v\nafter:  %v", beforeParams, afterParams)
	}
}

// TestClientHelloSpecForConn covers the copy itself: rewriting the connection's
// transport parameters leaves the caller's untouched, every other extension is shared,
// and a GREASE parameter keeps an ID that was already fixed but draws a fresh one per
// connection otherwise.
func TestClientHelloSpecForConn(t *testing.T) {
	pinned := &tls.GREASETransportParameter{IdOverride: 27 + 31*5, Length: 2}
	lazy := &tls.GREASETransportParameter{Length: 2}
	sni := &tls.SNIExtension{}
	qtp := &tls.QUICTransportParametersExtension{TransportParameters: tls.TransportParameters{
		tls.MaxIdleTimeout(30000),
		pinned,
		lazy,
		tls.InitialSourceConnectionID([]byte{}),
	}}
	chs := &tls.ClientHelloSpec{Extensions: []tls.TLSExtension{sni, qtp}}

	connCHS, connQTP := clientHelloSpecForConn(chs)
	if connCHS == chs || connQTP == qtp {
		t.Fatal("clientHelloSpecForConn returned the caller's spec or extension")
	}
	if connCHS.Extensions[1] != connQTP {
		t.Error("the copied spec does not carry the copied transport parameters extension")
	}
	if connCHS.Extensions[0] != sni {
		t.Error("other extensions should be shared with the caller's spec")
	}

	// What a connection does to its copy: suppression, a shuffle, the SCID fill-in, and
	// the GREASE draws when it is serialized.
	(&wire.TransportParameters{InitialSourceConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3})}).
		PopulateFromUQUIC(connQTP.TransportParameters)
	ShuffleQUICTransportParameters(connQTP)
	SuppressQUICTransportParameters(connQTP, []uint64{0x01})
	_ = connQTP.TransportParameters.Marshal()

	if len(qtp.TransportParameters) != 4 || chs.Extensions[1] != qtp {
		t.Fatal("the caller's transport parameters were changed")
	}
	if scid := qtp.TransportParameters[3].(tls.InitialSourceConnectionID); len(scid) != 0 {
		t.Errorf("the caller's initial_source_connection_id became %x", []byte(scid))
	}
	if pinned.IdOverride != 27+31*5 || len(pinned.ValueOverride) != 0 {
		t.Errorf("the caller's pinned GREASE parameter was changed: %#v", pinned)
	}
	if lazy.IdOverride != 0 || len(lazy.ValueOverride) != 0 {
		t.Errorf("the caller's GREASE parameter got the connection's random draw: %#v", lazy)
	}

	var gotIDs []uint64
	for _, tp := range connQTP.TransportParameters {
		if g, ok := tp.(*tls.GREASETransportParameter); ok {
			if g == pinned || g == lazy {
				t.Error("the connection shares a GREASE parameter with the caller's spec")
			}
			gotIDs = append(gotIDs, g.IdOverride)
		}
	}
	if len(gotIDs) != 2 || !slices.Contains(gotIDs, 27+31*5) {
		t.Errorf("connection GREASE IDs = %v, want the pinned %d plus one drawn", gotIDs, 27+31*5)
	}

	if spec, qtp := clientHelloSpecForConn(&tls.ClientHelloSpec{Extensions: []tls.TLSExtension{sni}}); qtp != nil || spec == nil {
		t.Error("a spec without a transport parameters extension should come back as is, with a nil extension")
	}
}
