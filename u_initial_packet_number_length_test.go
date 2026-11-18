package quic

import (
	"bytes"
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/refraction-networking/uquic/internal/handshake"
	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/wire"
	tls "github.com/refraction-networking/utls"
)

// uTestAckedPNManager is a uTestPNManager that also reports the largest acknowledged
// Initial, as the uQUIC sent packet handler does.
type uTestAckedPNManager struct {
	uTestPNManager
	largestAcked protocol.PacketNumber
}

func (m uTestAckedPNManager) LargestAcked(protocol.EncryptionLevel) protocol.PacketNumber {
	return m.largestAcked
}

// TestAppendInitialPacketPayloadPacketNumberLength covers Initials whose packet number
// does not fit the length the spec forces. PeekPacketNumber hands out the forced length
// unchecked, so a first packet number of 255 with InitPacketNumberLengths{1} sent packet
// number 256 as 0x00, which a server that has not processed packet 255 decodes as 0. The
// packet fails AEAD and the ClientHello is never assembled. It must be an error that
// names the packet number and both lengths, not a silently widened length.
func TestAppendInitialPacketPayloadPacketNumberLength(t *testing.T) {
	for _, tc := range []struct {
		name         string
		pn           protocol.PacketNumber
		pnLen        protocol.PacketNumberLen
		largestAcked protocol.PacketNumber
		wantErr      string
	}{
		{name: "255 in 1 byte, nothing acked", pn: 255, pnLen: 1, largestAcked: protocol.InvalidPacketNumber},
		{
			name: "256 in 1 byte, nothing acked", pn: 256, pnLen: 1, largestAcked: protocol.InvalidPacketNumber,
			wantErr: "uquic: Initial packet number 256 does not fit the 1-byte packet number length the QUICSpec forces (InitPacketNumberLength(s)); the peer needs at least 2 bytes to decode it (largest acknowledged Initial: none; RFC 9000 Section 17.1)",
		},
		{name: "256 in 2 bytes, nothing acked", pn: 256, pnLen: 2, largestAcked: protocol.InvalidPacketNumber},
		{name: "256 in 1 byte, 255 acked", pn: 256, pnLen: 1, largestAcked: 255},
		{name: "382 in 1 byte, 255 acked", pn: 382, pnLen: 1, largestAcked: 255},
		{
			name: "383 in 1 byte, 255 acked", pn: 383, pnLen: 1, largestAcked: 255,
			wantErr: "uquic: Initial packet number 383 does not fit the 1-byte packet number length the QUICSpec forces (InitPacketNumberLength(s)); the peer needs at least 2 bytes to decode it (largest acknowledged Initial: 255; RFC 9000 Section 17.1)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &uPacketPacker{
				packetPacker: &packetPacker{pnManager: uTestAckedPNManager{
					uTestPNManager: uTestPNManager{pn: tc.pn},
					largestAcked:   tc.largestAcked,
				}},
				uSpec: &QUICSpec{},
			}
			header := uTestInitialHeader()
			header.PacketNumber = tc.pn
			header.PacketNumberLen = tc.pnLen

			buffer := getPacketBuffer()
			bufferLenBefore := len(buffer.Data)
			_, err := p.appendInitialPacketPayload(buffer, header, payload{}, make([]byte, 64),
				0, protocol.EncryptionInitial, uTestSealer{overhead: 16}, protocol.Version1)

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("error = %v\nwant    %s", err, tc.wantErr)
			}
			if len(buffer.Data) != bufferLenBefore {
				t.Fatalf("buffer was written to despite the error: len %d, want %d", len(buffer.Data), bufferLenBefore)
			}
		})
	}
}

// dialDeadServer dials a UDP socket that never answers and returns every datagram the
// client sent along with Dial's error. Dial must give up on its own within the timeout.
func dialDeadServer(t *testing.T, spec *QUICSpec) ([][]byte, error) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, dialErr := tr.Dial(ctx, server.LocalAddr(), &tls.Config{InsecureSkipVerify: true}, &Config{})
	if errors.Is(dialErr, context.DeadlineExceeded) {
		t.Fatalf("Dial ran into the test timeout instead of failing: %v", dialErr)
	}

	var datagrams [][]byte
	for {
		if err := server.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2048)
		n, _, err := server.ReadFrom(buf)
		if err != nil {
			return datagrams, dialErr
		}
		datagrams = append(datagrams, buf[:n])
	}
}

// openInitialPayload decrypts a client Initial whose full packet number is pn and
// returns its frames, PADDING included.
func openInitialPayload(t *testing.T, datagram []byte, pn protocol.PacketNumber) []byte {
	t.Helper()

	hdr, pkt, _, err := wire.ParsePacket(datagram)
	if err != nil {
		t.Fatalf("parsing the long header: %v", err)
	}
	_, opener := handshake.NewInitialAEAD(hdr.DestConnectionID, protocol.PerspectiveServer, hdr.Version)
	pnOffset := int(hdr.ParsedLen())
	unprotected := slices.Clone(pkt[:pnOffset+4])
	opener.DecryptHeader(pkt[pnOffset+4:pnOffset+4+16], &unprotected[0], unprotected[pnOffset:])
	pnLen := int(unprotected[0]&0b11) + 1
	frames, err := opener.Open(nil, pkt[pnOffset+pnLen:], pn, unprotected[:pnOffset+pnLen])
	if err != nil {
		t.Fatalf("opening Initial packet number %d: %v", pn, err)
	}
	return frames
}

// TestInitialPacketNumberLengthOverflowDial is the boundary on a real connection, with a
// Firefox spec forcing 1-byte Initial packet numbers.
//
//   - First packet number 255: the first Initial goes out as 255 in 1 byte. Nothing
//     answers, so the PTO would retransmit the ClientHello as packet number 256, still
//     forced to 1 byte, i.e. as 0x00. Dial must fail on that packet instead.
//   - First packet number 256: Dial fails before anything is sent.
//
// The CONNECTION_CLOSE that follows the error is packed by upstream's
// PackConnectionClose, which this check does not cover, so it still carries the forced
// 1-byte length. The test only asserts that it is a close, not a ClientHello.
func TestInitialPacketNumberLengthOverflowDial(t *testing.T) {
	newSpec := func(firstPN uint64) *QUICSpec {
		spec, err := QUICID2Spec(QUICFirefox_116)
		if err != nil {
			t.Fatal(err)
		}
		spec.InitialPacketSpec.InitPacketNumber = firstPN
		spec.InitialPacketSpec.InitPacketNumberLengths = []PacketNumberLen{1}
		return &spec
	}
	const wantErr = "uquic: Initial packet number 256 does not fit the 1-byte packet number length the QUICSpec forces"

	t.Run("first PN 255", func(t *testing.T) {
		datagrams, err := dialDeadServer(t, newSpec(255))
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("Dial error = %v, want one containing %q", err, wantErr)
		}
		if len(datagrams) == 0 || len(datagrams) > 2 {
			t.Fatalf("client sent %d datagrams, want the first Initial and at most a CONNECTION_CLOSE", len(datagrams))
		}
		if _, pn, pnLen := parseInitial(t, datagrams[0]); pn != 255 || pnLen != 1 {
			t.Fatalf("first Initial: packet number %d in %d bytes, want 255 in 1", pn, pnLen)
		}
		if len(datagrams) == 2 {
			frames := bytes.TrimLeft(openInitialPayload(t, datagrams[1], 256), "\x00")
			if len(frames) == 0 || frames[0] != 0x1c {
				t.Fatalf("second datagram is not a CONNECTION_CLOSE: frames start % x", frames[:min(len(frames), 8)])
			}
		}
	})

	t.Run("first PN 256", func(t *testing.T) {
		datagrams, err := dialDeadServer(t, newSpec(256))
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("Dial error = %v, want one containing %q", err, wantErr)
		}
		if len(datagrams) != 0 {
			t.Fatalf("client sent %d datagrams, want none", len(datagrams))
		}
	})
}
