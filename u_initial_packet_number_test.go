package quic

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/refraction-networking/uquic/internal/handshake"
	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/wire"
	tls "github.com/refraction-networking/utls"
)

// dialAndCaptureFirstDatagram dials a dead UDP socket with the given spec and returns
// the first datagram the client puts on the wire, i.e. the first Initial.
func dialAndCaptureFirstDatagram(t *testing.T, spec *QUICSpec) []byte {
	t.Helper()

	var first []byte
	dialAndCaptureDatagrams(t, spec, func(datagram []byte) bool {
		first = datagram
		return false
	})
	return first
}

// dialAndCaptureDatagrams dials a dead UDP socket with the given spec and hands each
// datagram the client sends to onDatagram, stopping when it returns false. The client
// never completes a handshake — nothing answers — so this only ever observes the
// Initial flight and its retransmissions.
func dialAndCaptureDatagrams(t *testing.T, spec *QUICSpec, onDatagram func(datagram []byte) bool) {
	t.Helper()

	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	tr := &UTransport{Transport: &Transport{Conn: clientConn}, QUICSpec: spec}
	defer tr.Transport.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.Dial(ctx, server.LocalAddr(), &tls.Config{InsecureSkipVerify: true}, &Config{}) //nolint:errcheck // never completes; we only want the Initial
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("Dial did not return after cancellation")
		}
	}()

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		buf := make([]byte, 2048)
		n, _, err := server.ReadFrom(buf)
		if err != nil {
			if i == 0 {
				t.Fatalf("no Initial datagram received: %v", err)
			}
			t.Fatalf("client stopped sending after %d datagram(s): %v", i, err)
		}
		if !onDatagram(buf[:n]) {
			return
		}
	}
}

// parseInitial removes header protection from a client Initial and returns the header
// (with the token as sent) along with the wire packet number and its encoded length.
func parseInitial(t *testing.T, datagram []byte) (*wire.Header, protocol.PacketNumber, protocol.PacketNumberLen) {
	t.Helper()

	hdr, pkt, _, err := wire.ParsePacket(datagram)
	if err != nil {
		t.Fatalf("parsing the long header: %v", err)
	}
	if hdr.Type != protocol.PacketTypeInitial {
		t.Fatalf("first packet is %s, want Initial", hdr.Type)
	}

	// The server-side AEAD opens client packets; header protection uses a sample taken
	// 4 bytes past the start of the (max 4-byte) packet number field. See RFC 9001 §5.4.2.
	_, opener := handshake.NewInitialAEAD(hdr.DestConnectionID, protocol.PerspectiveServer, hdr.Version)
	pnOffset := int(hdr.ParsedLen())
	if len(pkt) < pnOffset+4+16 {
		t.Fatalf("packet too short (%d bytes) to sample header protection", len(pkt))
	}
	firstByte := pkt[0]
	pnBytes := make([]byte, 4)
	copy(pnBytes, pkt[pnOffset:pnOffset+4])
	opener.DecryptHeader(pkt[pnOffset+4:pnOffset+4+16], &firstByte, pnBytes)

	pnLen := protocol.PacketNumberLen(firstByte&0b11) + 1
	var pn protocol.PacketNumber
	for _, b := range pnBytes[:pnLen] {
		pn = pn<<8 | protocol.PacketNumber(b)
	}
	return hdr, pn, pnLen
}

// TestInitialPacketNumberFromSpec verifies that InitialPacketSpec.InitPacketNumber
// reaches the wire. It used to be consumed only as the index base for
// InitPacketNumberLengths while the Initial packet number space was seeded with a
// hardcoded 0, so every first Initial went out as PN=0 — a discriminator signal for
// Chrome, which starts its Initial flight at PN=1.
func TestInitialPacketNumberFromSpec(t *testing.T) {
	chrome146, err := QUICID2Spec(QUICChrome_146_IPv4)
	if err != nil {
		t.Fatal(err)
	}
	firefox116, err := QUICID2Spec(QUICFirefox_116)
	if err != nil {
		t.Fatal(err)
	}

	// Chrome 146 with a retry token and a pinned multi-datagram Initial flight: the
	// combination the fingerprint discriminator flagged (token present, but PN=0).
	tokenized, err := QUICID2Spec(QUICChrome_146_IPv4)
	if err != nil {
		t.Fatal(err)
	}
	tokenized.InitialPacketSpec.ClientTokenLength = 70
	tokenized.InitialPacketSpec.InitialPackets = []InitialPacketPlan{
		{CryptoLength: 999, PacketSize: 1200},
		{PacketSize: 1200},
	}

	for _, tc := range []struct {
		name      string
		spec      *QUICSpec
		wantPN    protocol.PacketNumber
		wantPNLen protocol.PacketNumberLen
		wantToken int
	}{
		{name: "chrome 146", spec: &chrome146, wantPN: 1, wantPNLen: 1},
		{name: "chrome 146 with token", spec: &tokenized, wantPN: 1, wantPNLen: 1, wantToken: 70},
		{name: "firefox 116", spec: &firefox116, wantPN: 0, wantPNLen: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hdr, pn, pnLen := parseInitial(t, dialAndCaptureFirstDatagram(t, tc.spec))
			if pn != tc.wantPN {
				t.Errorf("first Initial packet number = %d, want %d", pn, tc.wantPN)
			}
			if pnLen != tc.wantPNLen {
				t.Errorf("first Initial packet number length = %d, want %d", pnLen, tc.wantPNLen)
			}
			if len(hdr.Token) != tc.wantToken {
				t.Errorf("token length = %d, want %d", len(hdr.Token), tc.wantToken)
			}
		})
	}
}

// TestInitialPNHelper covers the spec-to-packet-number-space conversion, including the
// RFC 9000 §17.1 upper bound on packet numbers.
func TestInitialPNHelper(t *testing.T) {
	for _, tc := range []struct {
		in   uint64
		want protocol.PacketNumber
	}{
		{in: 0, want: 0},
		{in: 1, want: 1},
		{in: 1<<62 - 1, want: 1<<62 - 1},
		{in: 1 << 62, want: 0},   // out of range
		{in: 1<<64 - 1, want: 0}, // out of range, would wrap to a negative PN
	} {
		ps := &InitialPacketSpec{InitPacketNumber: tc.in}
		if got := ps.initialPN(); got != tc.want {
			t.Errorf("initialPN() for InitPacketNumber=%d = %d, want %d", tc.in, got, tc.want)
		}
	}
}
