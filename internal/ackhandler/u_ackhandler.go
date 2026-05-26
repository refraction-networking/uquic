package ackhandler

import (
	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/utils"
	"github.com/refraction-networking/uquic/qlogwriter"
)

// [UQUIC] NewUAckHandler creates a uSentPacketHandler that allows controlling the Initial
// packet number length. It only returns the SentPacketHandler; ReceivedPacketHandler is
// initialized separately by preSetup() in the connection struct.
func NewUAckHandler(
	initialPacketNumber protocol.PacketNumber,
	initialMaxDatagramSize protocol.ByteCount,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	clientAddressValidated bool,
	enableECN bool,
	ignorePacketsBelow func(protocol.PacketNumber),
	pers protocol.Perspective,
	qlogger qlogwriter.Recorder,
	logger utils.Logger,
) SentPacketHandler {
	sph := NewSentPacketHandler(initialPacketNumber, initialMaxDatagramSize, rttStats, connStats, clientAddressValidated, enableECN, ignorePacketsBelow, pers, qlogger, logger)
	return &uSentPacketHandler{
		sentPacketHandler: sph.(*sentPacketHandler),
	}
}
