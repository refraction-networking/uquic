package quic

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/qerr"
	"github.com/refraction-networking/uquic/internal/testdata"
	"github.com/refraction-networking/uquic/internal/wire"
	tls "github.com/refraction-networking/utls"

	"github.com/stretchr/testify/require"
)

func newTestConnIDManagerWithLimit(limit uint64) *connIDManager {
	m := newConnIDManager(
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		func(protocol.StatelessResetToken) {},
		func(protocol.StatelessResetToken) {},
		func(wire.Frame) {},
	)
	m.SetConnectionIDLimit(limit)
	return m
}

func testNewConnIDFrame(seq uint64, retirePriorTo uint64) *wire.NewConnectionIDFrame {
	b := byte(seq)
	return &wire.NewConnectionIDFrame{
		SequenceNumber:      seq,
		RetirePriorTo:       retirePriorTo,
		ConnectionID:        protocol.ParseConnectionID([]byte{b, b, b, b, 0xc1}),
		StatelessResetToken: protocol.StatelessResetToken{b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, 0xc1},
	}
}

// TestConnIDManagerAdvertisedLimit checks that the manager stores as many connection IDs
// as the spec advertised in active_connection_id_limit. SetConnectionIDLimit was a no-op
// after the quic-go v0.59.1 sync, so the queue stayed capped at
// protocol.MaxActiveConnectionIDs = 4 whatever the spec advertised: a Firefox spec
// (limit 8) died with CONNECTION_ID_LIMIT_ERROR right after the handshake against any
// server that issues more than 3 new connection IDs.
//
// RFC 9000 §18.2 counts the active connection ID towards the limit, so a peer may issue
// limit-1 new ones on top of it, and the limit-th is a violation.
func TestConnIDManagerAdvertisedLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit uint64
		// newConnIDs is how many NEW_CONNECTION_ID frames must be accepted on top of
		// the active connection ID. One more must fail.
		newConnIDs uint64
	}{
		{name: "unset keeps the upstream cap", limit: 0, newConnIDs: protocol.MaxActiveConnectionIDs - 1},
		{name: "RFC default 2", limit: 2, newConnIDs: 1},
		{name: "upstream value 4", limit: 4, newConnIDs: 3},
		{name: "Firefox 8", limit: 8, newConnIDs: 7},
		{name: "Safari 64", limit: 64, newConnIDs: 63},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestConnIDManagerWithLimit(tc.limit)
			for seq := uint64(1); seq <= tc.newConnIDs; seq++ {
				require.NoError(t, m.Add(testNewConnIDFrame(seq, 0)), "connection ID %d of %d", seq, tc.newConnIDs)
			}
			require.Equal(t,
				&qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError},
				m.Add(testNewConnIDFrame(tc.newConnIDs+1, 0)),
			)
		})
	}
}

// TestConnIDManagerAdvertisedLimitWithRetirement checks that a peer staying at the limit
// by retiring old connection IDs (retire_prior_to) is not counted against it.
func TestConnIDManagerAdvertisedLimitWithRetirement(t *testing.T) {
	m := newTestConnIDManagerWithLimit(8)
	for seq := uint64(1); seq <= 7; seq++ {
		require.NoError(t, m.Add(testNewConnIDFrame(seq, 0)))
	}
	// Retires sequence numbers 0 (active) and 1, adds 8: 7 spare connection IDs remain
	// once the active one has moved on to 2.
	require.NoError(t, m.Add(testNewConnIDFrame(8, 2)))
	require.Equal(t, testNewConnIDFrame(2, 0).ConnectionID, m.Get())
	require.Len(t, m.queue, 6)
	require.NoError(t, m.Add(testNewConnIDFrame(9, 0)))
	require.Error(t, m.Add(testNewConnIDFrame(10, 0)))
}

// TestConnIDManagerRotationIgnoresAdvertisedLimit pins down that the rotation heuristic
// still wants protocol.MaxActiveConnectionIDs/2 spare connection IDs, however many the
// spec lets the peer issue. Measured against a limit of 64 instead, a connection would
// stop rotating after its first switch against a quic-go server, which issues 5.
func TestConnIDManagerRotationIgnoresAdvertisedLimit(t *testing.T) {
	m := newTestConnIDManagerWithLimit(64)
	for seq := uint64(1); seq <= 3; seq++ {
		require.NoError(t, m.Add(testNewConnIDFrame(seq, 0)))
	}
	m.SetHandshakeComplete()
	require.Equal(t, testNewConnIDFrame(1, 0).ConnectionID, m.Get()) // first switch: as soon as possible
	for range 2 * protocol.PacketsPerConnectionID {
		m.SentPacket()
	}
	require.Equal(t, testNewConnIDFrame(2, 0).ConnectionID, m.Get()) // 2 spare: 2*2 >= MaxActiveConnectionIDs
}

// TestUTransportAdvertisedConnIDLimit is the end-to-end version: a Firefox spec, which
// advertises active_connection_id_limit 8, dials a local quic-go server. The server issues
// min(8, protocol.MaxIssuedConnectionIDs)-1 = 5 new connection IDs right after the
// handshake. With the queue capped at 4 the client closed the connection with
// CONNECTION_ID_LIMIT_ERROR as soon as they arrived, so the echo below never came back.
func TestUTransportAdvertisedConnIDLimit(t *testing.T) {
	spec, err := QUICID2Spec(QUICFirefox_116)
	require.NoError(t, err)

	serverTLS := testdata.GetTLSConfig()
	serverTLS.NextProtos = []string{"h3"}
	ln, err := ListenAddr("127.0.0.1:0", serverTLS, &Config{})
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		str, err := conn.AcceptStream(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		_, err = io.Copy(str, str)
		if err == nil {
			err = str.Close()
		}
		serverErr <- err
		<-ctx.Done() // keep the server side open until the client is done
	}()

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	tr := &UTransport{Transport: &Transport{Conn: udpConn}, QUICSpec: &spec}
	defer tr.Transport.Close()

	conn, err := tr.Dial(ctx, ln.Addr(), &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"}, &Config{})
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	str, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	_, err = str.Write([]byte("ping"))
	require.NoError(t, err)
	require.NoError(t, str.Close())
	echo, err := io.ReadAll(str)
	require.NoError(t, err, "connection closed: %v", context.Cause(conn.Context()))
	require.Equal(t, "ping", string(echo))
	require.NoError(t, <-serverErr)

	select {
	case <-conn.Context().Done():
		t.Fatalf("connection closed after the echo: %v", context.Cause(conn.Context()))
	case <-time.After(100 * time.Millisecond):
	}
}
