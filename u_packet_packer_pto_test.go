package quic

import (
	"testing"

	"github.com/refraction-networking/uquic/internal/monotime"
	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// A 1-RTT probe with nothing to send carries a PING when asked to, as the
// packetPacker's does, rather than leaving the connection with no probe.
func TestUPackPTOProbePacket1RTTNothingToPack(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	packer := &uPacketPacker{packetPacker: tp.packer}
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil).Times(2)
	tp.framer.EXPECT().HasData().Times(2)
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2).Times(2)
	tp.ackFramer.EXPECT().GetAckFrame(protocol.Encryption1RTT, gomock.Any(), true).Times(2)

	packet, err := packer.PackPTOProbePacket(protocol.Encryption1RTT, 1234, false, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.Nil(t, packet)

	tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(0x42))
	packet, err = packer.PackPTOProbePacket(protocol.Encryption1RTT, 1234, true, monotime.Now(), protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, packet)
	require.NotNil(t, packet.shortHdrPacket)
	require.Len(t, packet.shortHdrPacket.Frames, 1)
	require.Equal(t, &wire.PingFrame{}, packet.shortHdrPacket.Frames[0].Frame)
}
