package quic

import (
	"context"
	"errors"
	"net"

	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/utils"
	"github.com/refraction-networking/uquic/qlogwriter"
	tls "github.com/refraction-networking/utls"
)

type UTransport struct {
	*Transport

	QUICSpec *QUICSpec // [UQUIC] using ptr to avoid copying
}

// Dial dials a new connection to a remote host (not using 0-RTT).
func (t *UTransport) Dial(ctx context.Context, addr net.Addr, tlsConf *tls.Config, conf *Config) (*Conn, error) {
	return t.dial(ctx, addr, "", tlsConf, conf, false)
}

// DialEarly dials a new connection, attempting to use 0-RTT if possible.
func (t *UTransport) DialEarly(ctx context.Context, addr net.Addr, tlsConf *tls.Config, conf *Config) (*Conn, error) {
	return t.dial(ctx, addr, "", tlsConf, conf, true)
}

func (t *UTransport) dial(ctx context.Context, addr net.Addr, host string, tlsConf *tls.Config, conf *Config, use0RTT bool) (*Conn, error) {
	// [UQUIC]
	// Set the source connection ID generator from the spec BEFORE init(). init()
	// caches t.ConnectionIDGenerator into the internal t.connIDGenerator (which
	// doDial uses to generate the source connection ID), so setting it afterwards
	// had no effect — SrcConnIDLength (including 0 → empty SCID) was silently
	// ignored and the SCID always got the default length.
	if t.QUICSpec != nil {
		if t.QUICSpec.InitialPacketSpec.SrcConnIDLength != 0 {
			t.ConnectionIDGenerator = &protocol.DefaultConnectionIDGenerator{ConnLen: t.QUICSpec.InitialPacketSpec.SrcConnIDLength}
		} else {
			t.ConnectionIDGenerator = &protocol.ExpEmptyConnectionIDGenerator{}
		}
	}
	// [/UQUIC]

	if err := t.init(t.isSingleUse); err != nil {
		return nil, err
	}
	if err := validateConfig(conf); err != nil {
		return nil, err
	}
	conf = populateConfig(conf)

	tlsConf = tlsConf.Clone()
	setTLSConfigServerName(tlsConf, addr, host)
	return t.doDial(ctx,
		newSendConn(t.conn, addr, packetInfo{}, utils.DefaultLogger),
		tlsConf,
		conf,
		0,
		false,
		use0RTT,
		conf.Versions[0],
	)
}

func (t *UTransport) doDial(
	ctx context.Context,
	sendConn sendConn,
	tlsConf *tls.Config,
	config *Config,
	initialPacketNumber protocol.PacketNumber,
	hasNegotiatedVersion bool,
	use0RTT bool,
	version protocol.Version,
) (*Conn, error) {
	srcConnID, err := t.connIDGenerator.GenerateConnectionID()
	if err != nil {
		return nil, err
	}
	// [UQUIC] Honor the spec's DestConnIDLength for the initial (client-chosen)
	// destination connection ID; fall back to a random-length one otherwise.
	// Without this, InitialPacketSpec.DestConnIDLength was silently ignored and
	// the initial DCID got a random length, making the fingerprint unstable.
	var destConnID protocol.ConnectionID
	if t.QUICSpec != nil && t.QUICSpec.InitialPacketSpec.DestConnIDLength > 0 {
		destConnID, err = generateConnectionIDForInitialWithLength(t.QUICSpec.InitialPacketSpec.DestConnIDLength)
	} else {
		destConnID, err = generateConnectionIDForInitial()
	}
	if err != nil {
		return nil, err
	}

	t.mutex.Lock()
	if t.closeErr != nil {
		t.mutex.Unlock()
		return nil, t.closeErr
	}

	var qlogTrace qlogwriter.Trace
	if config.Tracer != nil {
		qlogTrace = config.Tracer(ctx, true, destConnID)
	}

	logger := utils.DefaultLogger.WithPrefix("client")
	logger.Infof("Starting new connection to %s (%s -> %s), source connection ID %s, destination connection ID %s, version %s", tlsConf.ServerName, sendConn.LocalAddr(), sendConn.RemoteAddr(), srcConnID, destConnID, version)

	// [uQUIC SECTION BEGIN]
	var conn *wrappedConn
	if t.QUICSpec == nil {
		conn = newClientConnection(
			context.WithoutCancel(ctx),
			sendConn,
			(*packetHandlerMap)(t.Transport),
			destConnID,
			srcConnID,
			t.connIDGenerator,
			t.statelessResetter,
			config,
			tlsConf,
			initialPacketNumber,
			use0RTT,
			hasNegotiatedVersion,
			qlogTrace,
			logger,
			version,
		)
	} else {
		conn = newUClientConnection(
			context.WithoutCancel(ctx),
			sendConn,
			(*packetHandlerMap)(t.Transport),
			destConnID,
			srcConnID,
			t.connIDGenerator,
			t.statelessResetter,
			config,
			tlsConf,
			initialPacketNumber,
			use0RTT,
			hasNegotiatedVersion,
			qlogTrace,
			logger,
			version,
			t.QUICSpec,
		)
	}
	// [uQUIC SECTION END]

	t.handlers[srcConnID] = conn
	t.mutex.Unlock()

	// The error channel needs to be buffered, as the run loop will continue running
	// after doDial returns (if the handshake is successful).
	// Similarly, the recreateChan needs to be buffered; in case a different case is selected.
	errChan := make(chan error, 1)
	recreateChan := make(chan errCloseForRecreating, 1)
	go func() {
		err := conn.run()
		var recreateErr *errCloseForRecreating
		if errors.As(err, &recreateErr) {
			recreateChan <- *recreateErr
			return
		}
		if t.isSingleUse {
			t.Close()
		}
		errChan <- err
	}()

	// Only set when we're using 0-RTT.
	// Otherwise, earlyConnChan will be nil. Receiving from a nil chan blocks forever.
	var earlyConnChan <-chan struct{}
	if use0RTT {
		earlyConnChan = conn.earlyConnReady()
	}

	select {
	case <-ctx.Done():
		conn.destroy(nil)
		// wait until the Go routine that called Connection.run() returns
		select {
		case <-errChan:
		case <-recreateChan:
		}
		return nil, context.Cause(ctx)
	case params := <-recreateChan:
		return t.doDial(ctx,
			sendConn,
			tlsConf,
			config,
			params.nextPacketNumber,
			true,
			use0RTT,
			params.nextVersion,
		)
	case err := <-errChan:
		return nil, err
	case <-earlyConnChan:
		// ready to send 0-RTT data
		return conn.Conn, nil
	case <-conn.HandshakeComplete():
		// handshake successfully completed
		return conn.Conn, nil
	}
}

func (ut *UTransport) MakeDialer() func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *Config) (*Conn, error) {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *Config) (*Conn, error) {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, err
		}
		return ut.DialEarly(ctx, udpAddr, tlsCfg, cfg)
	}
}
