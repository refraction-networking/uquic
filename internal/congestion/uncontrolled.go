package congestion

import (
	"github.com/refraction-networking/uquic/internal/monotime"
	"github.com/refraction-networking/uquic/internal/protocol"
)

// uncontrolled never holds a packet back, nor paces one: the transport the
// packets travel over controls congestion, as TCP does.
type uncontrolled struct{}

// NewUncontrolled is a SendAlgorithm for a connection whose transport
// controls congestion itself.
func NewUncontrolled() SendAlgorithmWithDebugInfos { return uncontrolled{} }

func (uncontrolled) TimeUntilSend(protocol.ByteCount) monotime.Time { return 0 }
func (uncontrolled) HasPacingBudget(monotime.Time) bool             { return true }
func (uncontrolled) OnPacketSent(monotime.Time, protocol.ByteCount, protocol.PacketNumber, protocol.ByteCount, bool) {
}
func (uncontrolled) CanSend(protocol.ByteCount) bool { return true }
func (uncontrolled) MaybeExitSlowStart()             {}
func (uncontrolled) OnPacketAcked(protocol.PacketNumber, protocol.ByteCount, protocol.ByteCount, monotime.Time) {
}
func (uncontrolled) OnCongestionEvent(protocol.PacketNumber, protocol.ByteCount, protocol.ByteCount) {
}
func (uncontrolled) OnRetransmissionTimeout(bool)            {}
func (uncontrolled) SetMaxDatagramSize(protocol.ByteCount)   {}
func (uncontrolled) InSlowStart() bool                       { return false }
func (uncontrolled) InRecovery() bool                        { return false }
func (uncontrolled) GetCongestionWindow() protocol.ByteCount { return protocol.MaxByteCount }
