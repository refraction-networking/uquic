package quic

import (
	"testing"

	"github.com/refraction-networking/uquic/internal/mocks"
	mockackhandler "github.com/refraction-networking/uquic/internal/mocks/ackhandler"
	"github.com/refraction-networking/uquic/internal/monotime"
	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestConnectionDatagramBudgetAfterMTUDiscovery(t *testing.T) {
	ctrl := gomock.NewController(t)
	sent := mockackhandler.NewMockSentPacketHandler(ctrl)
	crypto := mocks.NewMockCryptoSetup(ctrl)
	mtu := NewMockMTUDiscoverer(ctrl)
	tc := newServerTestConnection(t, ctrl, &Config{EnableDatagrams: true, InitialPacketSize: 1200}, false,
		connectionOptSentPacketHandler(sent), connectionOptCryptoSetup(crypto))
	c := tc.conn
	c.peerParams = &wire.TransportParameters{MaxDatagramFrameSize: 65535}
	c.mtuDiscoverer = mtu
	ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}}
	sent.EXPECT().ReceivedAck(ack, protocol.Encryption1RTT, gomock.Any()).Return(true, nil)
	mtu.EXPECT().CurrentSize().Return(protocol.ByteCount(1452))
	sent.EXPECT().SetMaxDatagramSize(protocol.ByteCount(1452))
	crypto.EXPECT().SetLargest1RTTAcked(protocol.PacketNumber(1)).Return(nil)
	require.NoError(t, c.handleAckFrame(ack, protocol.Encryption1RTT, monotime.Now()))

	var limit *DatagramTooLargeError
	require.ErrorAs(t, c.SendDatagram(make([]byte, 65536)), &limit)
	payload := make([]byte, int(limit.MaxDatagramPayloadSize))
	frame := &wire.DatagramFrame{Data: payload, DataLenPresent: true}
	packetLen := wire.ShortHeaderLen(c.connIDManager.Get(), protocol.PacketNumberLen4) + frame.Length(c.version) + 16
	require.LessOrEqual(t, packetLen, protocol.ByteCount(1452), "accepted payload must fit the discovered packet MTU")
	require.NoError(t, c.SendDatagram(payload))
	require.Equal(t, payload, c.datagramQueue.Peek().Data)
	require.Error(t, c.SendDatagram(make([]byte, len(payload)+1)))
}

func TestConnectionDatagramBudgetOnLocalMigration(t *testing.T) {
	ctrl := gomock.NewController(t)
	sent := mockackhandler.NewMockSentPacketHandler(ctrl)
	sender := NewMockSender(ctrl)
	mtu := NewMockMTUDiscoverer(ctrl)
	tc := newClientTestConnection(t, ctrl, nil, false,
		connectionOptSentPacketHandler(sent), connectionOptSender(sender))
	c := tc.conn
	c.peerParams = &wire.TransportParameters{MaxUDPPayloadSize: 1452}
	c.mtuDiscoverer = mtu
	c.currentPacketMTU.Store(1452)
	tr := &Transport{Conn: newUDPConnLocalhost(t)}
	require.NoError(t, tr.init(false))
	defer tr.Close()
	now := monotime.Now()
	initialMTU := protocol.ByteCount(c.config.InitialPacketSize)
	sent.EXPECT().MigratedPath(now, initialMTU)
	mtu.EXPECT().Reset(now, initialMTU, protocol.ByteCount(1452))
	sender.EXPECT().Close()
	c.switchToNewPath(tr, now)
	defer c.sendQueue.Close()
	require.Equal(t, uint32(initialMTU), c.currentPacketMTU.Load())
}

func TestConnectionDatagramPayloadLimit(t *testing.T) {
	tc := newServerTestConnection(t, nil, &Config{EnableDatagrams: true, InitialPacketSize: 1200}, false)
	c := tc.conn
	for _, cidLen := range []int{0, 4, 8, 20} {
		c.connIDManager = newConnIDManager(protocol.ParseConnectionID(make([]byte, cidLen)), nil, nil, nil)
		for _, packetMTU := range []uint32{1200, 1452} {
			c.currentPacketMTU.Store(packetMTU)
			for _, peerMax := range []protocol.ByteCount{0, 100, 65535} {
				c.peerParams = &wire.TransportParameters{MaxDatagramFrameSize: peerMax}
				limit := c.DatagramPayloadLimit()
				if peerMax == 0 {
					require.Zero(t, limit)
					continue
				}
				var tooLarge *DatagramTooLargeError
				require.ErrorAs(t, c.SendDatagram(make([]byte, int(limit)+1)), &tooLarge)
				require.Equal(t, limit, tooLarge.MaxDatagramPayloadSize)
				payload := make([]byte, int(limit))
				frame := &wire.DatagramFrame{Data: payload, DataLenPresent: true}
				require.LessOrEqual(t, frame.Length(c.version), peerMax)
				packetLen := wire.ShortHeaderLen(c.connIDManager.Get(), protocol.PacketNumberLen4) + frame.Length(c.version) + 16
				require.LessOrEqual(t, packetLen, protocol.ByteCount(packetMTU))
				require.NoError(t, c.SendDatagram(payload))
				c.datagramQueue.Pop()
			}
		}
	}
}

func TestConnectionDatagramPayloadLimitConcurrentCIDUpdates(t *testing.T) {
	tc := newServerTestConnection(t, nil, &Config{EnableDatagrams: true}, false)
	c := tc.conn
	c.peerParams = &wire.TransportParameters{MaxDatagramFrameSize: 65535}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			c.DatagramPayloadLimit()
		}
	}()
	for range 100 {
		for cidLen := 1; cidLen <= 20; cidLen++ {
			c.connIDManager.ChangeInitialConnID(protocol.ParseConnectionID(make([]byte, cidLen)))
		}
	}
	<-done
	longCIDLimit := c.DatagramPayloadLimit()
	c.connIDManager.ChangeInitialConnID(protocol.ParseConnectionID(make([]byte, 4)))
	require.Equal(t, longCIDLimit, c.DatagramPayloadLimit(), "retain the budget for every known peer CID")
	require.NoError(t, c.connIDManager.AddFromPreferredAddress(protocol.ParseConnectionID(make([]byte, 20)), protocol.StatelessResetToken{}))
	require.Equal(t, longCIDLimit, c.DatagramPayloadLimit())
}
