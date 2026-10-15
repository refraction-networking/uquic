package quic

import (
	"strings"
	"testing"

	"github.com/refraction-networking/uquic/internal/monotime"
	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// uTestSealer is a no-op sealer: these tests only exercise packet sizing, so all that
// matters is Overhead(). Seal writes nothing, which is fine because encryptPacket
// discards its return value and just reslices by Overhead().
type uTestSealer struct{ overhead int }

func (s uTestSealer) Seal(dst, _ []byte, _ protocol.PacketNumber, _ []byte) []byte { return dst }
func (s uTestSealer) EncryptHeader(_ []byte, _ *byte, _ []byte)                    {}
func (s uTestSealer) Overhead() int                                                { return s.overhead }
func (s uTestSealer) DecryptHeader(_ []byte, _ *byte, _ []byte)                    {}

// uTestPNManager hands out one fixed packet number, so the Peeked/Popped consistency
// check at the end of appendInitialPacketPayload passes.
type uTestPNManager struct{ pn protocol.PacketNumber }

func (m uTestPNManager) PeekPacketNumber(protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen) {
	return m.pn, protocol.PacketNumberLen4
}
func (m uTestPNManager) PopPacketNumber(protocol.EncryptionLevel) protocol.PacketNumber { return m.pn }

func uTestInitialHeader() *wire.ExtendedHeader {
	return &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeInitial,
			DestConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
			SrcConnectionID:  protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			Version:          protocol.Version1,
		},
		PacketNumber:    0,
		PacketNumberLen: protocol.PacketNumberLen4,
	}
}

// TestAppendInitialPacketPayloadOversize covers the frame payload that does not fit the
// packet buffer. The frame builder and the spec's PacketSize decide how many bytes reach
// appendInitialPacketPayload, and neither is bounded by quic-go's payload sizing, so an
// oversized one used to run off the end of buffer.Data and panic on the reslice
// ("slice bounds out of range ... with capacity 1452"). It must be a returned error.
func TestAppendInitialPacketPayloadOversize(t *testing.T) {
	sealer := uTestSealer{overhead: 16}

	for _, tc := range []struct {
		name       string
		payloadLen int
		packetSize int
	}{
		{name: "frame builder overshoots the datagram", payloadLen: protocol.MaxPacketBufferSize},
		{name: "spec PacketSize larger than the buffer", payloadLen: 64, packetSize: protocol.MaxPacketBufferSize + 48},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &uPacketPacker{
				packetPacker: &packetPacker{pnManager: uTestPNManager{}},
				uSpec:        &QUICSpec{},
			}
			if tc.packetSize > 0 {
				p.uSpec.InitialPacketSpec.InitialPackets = []InitialPacketPlan{{PacketSize: tc.packetSize}}
			}

			buffer := getPacketBuffer()
			bufferLenBefore := len(buffer.Data)

			pkt, err := p.appendInitialPacketPayload(buffer, uTestInitialHeader(), payload{},
				make([]byte, tc.payloadLen), 0, protocol.EncryptionInitial, sealer, protocol.Version1)
			if err == nil {
				t.Fatalf("Expected an error for a %d-byte payload, got a %d-byte packet", tc.payloadLen, pkt.length)
			}
			if !strings.Contains(err.Error(), "does not fit the packet buffer") {
				t.Fatalf("Unexpected error: %v", err)
			}
			if len(buffer.Data) != bufferLenBefore {
				t.Fatalf("Buffer was written to despite the error: len %d, want %d", len(buffer.Data), bufferLenBefore)
			}
		})
	}
}

// TestAppendInitialPacketPayloadExactFit is the other side of the bounds check: a payload
// filling the buffer to the last byte must still be sent. An over-strict check here would
// silently reject specs that fit.
func TestAppendInitialPacketPayloadExactFit(t *testing.T) {
	sealer := uTestSealer{overhead: 16}
	header := uTestInitialHeader()
	maxPayload := protocol.MaxPacketBufferSize - int(header.GetLength(protocol.Version1)) - sealer.Overhead()

	p := &uPacketPacker{
		packetPacker: &packetPacker{pnManager: uTestPNManager{}},
		uSpec:        &QUICSpec{},
	}
	buffer := getPacketBuffer()

	pkt, err := p.appendInitialPacketPayload(buffer, header, payload{}, make([]byte, maxPayload),
		0, protocol.EncryptionInitial, sealer, protocol.Version1)
	if err != nil {
		t.Fatalf("Failed to append a %d-byte payload that fits exactly: %v", maxPayload, err)
	}
	if pkt.length != protocol.ByteCount(protocol.MaxPacketBufferSize) {
		t.Fatalf("Packet length mismatch: got %d, want %d", pkt.length, protocol.MaxPacketBufferSize)
	}
	if len(buffer.Data) != protocol.MaxPacketBufferSize {
		t.Fatalf("Buffer length mismatch: got %d, want %d", len(buffer.Data), protocol.MaxPacketBufferSize)
	}
}

func TestUPackerEmpty1RTTProbe(t *testing.T) {
	ctrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
	p := newUPacketPacker(tp.packer, &QUICSpec{})
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(ctrl), nil).Times(2)
	tp.framer.EXPECT().HasData().Times(2)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2).MaxTimes(2)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true).Times(2)

	packet, err := p.PackPTOProbePacket(protocol.Encryption1RTT, 1200, false, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Nil(t, packet)

	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	packet, err = p.PackPTOProbePacket(protocol.Encryption1RTT, 1200, true, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, packet)
	defer packet.buffer.Release()
	require.NotNil(t, packet.shortHdrPacket)
	require.Len(t, packet.shortHdrPacket.Frames, 1)
	require.Equal(t, &wire.PingFrame{}, packet.shortHdrPacket.Frames[0].Frame)
}
