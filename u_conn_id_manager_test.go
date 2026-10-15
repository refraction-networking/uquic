package quic

import (
	"fmt"
	"testing"

	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/qerr"
	"github.com/refraction-networking/uquic/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestConnIDManagerAdvertisedLimit(t *testing.T) {
	for _, limit := range []uint64{0, 2, 4, 8} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			m := newConnIDManager(protocol.ParseConnectionID([]byte{0}),
				func(protocol.StatelessResetToken) {}, func(protocol.StatelessResetToken) {}, func(wire.Frame) {})
			m.SetConnectionIDLimit(limit)
			effectiveLimit := limit
			if effectiveLimit == 0 {
				effectiveLimit = 2 // RFC 9000 default when the parameter is omitted.
			}
			for i := uint64(1); i < effectiveLimit; i++ {
				require.NoError(t, m.Add(&wire.NewConnectionIDFrame{
					SequenceNumber: i, ConnectionID: protocol.ParseConnectionID([]byte{byte(i)}),
				}))
			}
			require.ErrorIs(t, m.Add(&wire.NewConnectionIDFrame{
				SequenceNumber: effectiveLimit, ConnectionID: protocol.ParseConnectionID([]byte{byte(effectiveLimit)}),
			}), &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError})
		})
	}
}

func TestConnIDManagerRotationUsesAdvertisedLimit(t *testing.T) {
	m := newConnIDManager(protocol.ParseConnectionID([]byte{0}), nil, nil, nil)
	m.SetConnectionIDLimit(8)
	m.handshakeComplete = true
	m.activeSequenceNumber = 1
	m.packetsSinceLastChange = m.packetsPerConnectionID
	m.queue = make([]newConnID, 3)
	require.False(t, m.shouldUpdateConnID())
	m.queue = append(m.queue, newConnID{})
	require.True(t, m.shouldUpdateConnID())
}
