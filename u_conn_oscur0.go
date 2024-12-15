package quic

import (
	"net"

	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/utils"
	"github.com/refraction-networking/uquic/logging"
)

func oscur0ServerConn(pconn net.PacketConn, remoteAddr net.Addr) (Connection, error) {
	c := &connection{}

	c.handshakeDestConnID = protocol.ParseConnectionID([]uint8{38, 67, 73, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	c.origDestConnID = protocol.ParseConnectionID([]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	c.retrySrcConnID = nil
	c.srcConnIDLen = 4
	c.perspective = logging.PerspectiveServer
	c.version = Version1

	rconn, err := wrapConn(pconn)
	if err != nil {
		return nil, err
	}
	c.conn = newSendConn(rconn, remoteAddr, packetInfo{}, utils.DefaultLogger)
	c.sendQueue = newSendQueue(c.conn)
	c.streamsMap = newStreamsMap(c, c.newFlowController, 100, 100, c.perspective)
	handlermap := newPacketHandlerMap(c.statelessReset)
	c.connIDManager = newConnIDManager(
		c.origDestConnID,
		func(token protocol.StatelessResetToken) { runner.AddResetToken(token, s) },
		runner.RemoveResetToken,
		s.queueControlFrame,
	)
	return c, nil
}
