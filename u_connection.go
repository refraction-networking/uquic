package quic

import (
	"context"
	"slices"

	"github.com/refraction-networking/uquic/internal/ackhandler"
	"github.com/refraction-networking/uquic/internal/handshake"
	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/utils"
	"github.com/refraction-networking/uquic/internal/wire"
	"github.com/refraction-networking/uquic/qlogwriter"
	tls "github.com/refraction-networking/utls"
)

// [UQUIC]
var newUClientConnection = func(
	ctx context.Context,
	conn sendConn,
	runner connRunner,
	destConnID protocol.ConnectionID,
	srcConnID protocol.ConnectionID,
	connIDGenerator ConnectionIDGenerator,
	statelessResetter *statelessResetter,
	conf *Config,
	tlsConf *tls.Config,
	initialPacketNumber protocol.PacketNumber,
	enable0RTT bool,
	hasNegotiatedVersion bool,
	qlogTrace qlogwriter.Trace,
	logger utils.Logger,
	v protocol.Version,
	uSpec *QUICSpec, // [UQUIC]
) *wrappedConn {
	s := &Conn{
		conn:                conn,
		config:              conf,
		origDestConnID:      destConnID,
		handshakeDestConnID: destConnID,
		srcConnIDLen:        srcConnID.Len(),
		perspective:         protocol.PerspectiveClient,
		logID:               destConnID.String(),
		logger:              logger,
		qlogTrace:           qlogTrace,
		versionNegotiated:   hasNegotiatedVersion,
		version:             v,
	}
	if qlogTrace != nil {
		s.qlogger = qlogTrace.AddProducer()
	}
	s.connIDManager = newConnIDManager(
		destConnID,
		func(token protocol.StatelessResetToken) { runner.AddResetToken(token, s) },
		runner.RemoveResetToken,
		s.queueControlFrame,
	)

	s.connIDGenerator = newConnIDGenerator(
		runner,
		srcConnID,
		nil,
		statelessResetter,
		connRunnerCallbacks{
			AddConnectionID:    func(connID protocol.ConnectionID) { runner.Add(connID, s) },
			RemoveConnectionID: runner.Remove,
			ReplaceWithClosed:  runner.ReplaceWithClosed,
		},
		s.queueControlFrame,
		connIDGenerator,
	)
	s.ctx, s.ctxCancel = context.WithCancelCause(ctx)
	s.preSetup()
	// [UQUIC] A QUICSpec is authoritative over the Initial CRYPTO framing (via
	// InitialPacketSpec.FrameBuilder), and uPacketPacker re-frames every Initial
	// datagram. The upstream anti-DPI ClientHello scrambler would cut the stream at
	// the SNI/ECH, producing non-contiguous CRYPTO frames that the re-framing path
	// cannot reassemble (breaks multi-datagram Initials, e.g. Chrome 146). Disable it.
	s.initialStream.DisableScrambling()
	s.sentPacketHandler = ackhandler.NewUAckHandler(
		initialPacketNumber,
		protocol.ByteCount(s.config.InitialPacketSize),
		s.rttStats,
		&s.connStats,
		false, // has no effect
		s.conn.capabilities().ECN,
		s.receivedPacketHandler.IgnorePacketsBelow,
		s.perspective,
		s.qlogger,
		s.logger,
	)
	s.currentPacketMTU.Store(uint32(s.config.InitialPacketSize))
	// [UQUIC] Set Initial packet number encoding length.
	// Per-packet list takes precedence over single-value override.
	if len(uSpec.InitialPacketSpec.InitPacketNumberLengths) > 0 {
		ackhandler.SetInitialPacketNumberLengths(
			s.sentPacketHandler,
			protocol.PacketNumber(uSpec.InitialPacketSpec.InitPacketNumber),
			uSpec.InitialPacketSpec.InitPacketNumberLengths,
		)
	} else if uSpec.InitialPacketSpec.InitPacketNumberLength != 0 {
		ackhandler.SetInitialPacketNumberLength(s.sentPacketHandler, uSpec.InitialPacketSpec.InitPacketNumberLength)
	}

	oneRTTStream := newCryptoStream()

	var params *wire.TransportParameters

	// [UQUIC] The ClientHelloSpec this connection hands to uTLS. When the spec has one,
	// it is a per-connection copy (see clientHelloSpecForConn), never the caller's.
	chs := uSpec.ClientHelloSpec

	if chs != nil {
		var qtp *tls.QUICTransportParametersExtension
		chs, qtp = clientHelloSpecForConn(chs)
		if qtp == nil {
			panic("applied ClientHelloSpec must contain a QUICTransportParametersExtension to proceed")
		}
		params = &wire.TransportParameters{
			InitialSourceConnectionID: srcConnID,
		}
		// [UQUIC] uTLS serializes qtp.TransportParameters directly into the ClientHello
		// (the wire) via ApplyPreset below, so every rewrite here must happen now, on
		// that exact slice. qtp belongs to this connection alone, so none of them reach
		// the caller's spec, and the next connection from the same spec starts from the
		// parameters as declared.
		//
		// Drop suppressed parameters first, so what follows (the shuffle, and
		// PopulateFromUQUIC's view of our own parameters) sees exactly the set that
		// goes on the wire.
		SuppressQUICTransportParameters(qtp, uSpec.SuppressTransportParameters)
		// Real Chrome randomizes the QUIC transport parameter wire order on every
		// handshake. When the spec opts in, shuffle the parameters into a fresh
		// uniformly random permutation per connection so the order can't be used as a
		// discriminator signal.
		if uSpec.RandomizeTransportParameters {
			ShuffleQUICTransportParameters(qtp)
		}
		// This also fills a zero-length initial_source_connection_id with this
		// connection's real source connection ID.
		params.PopulateFromUQUIC(qtp.TransportParameters)
		s.connIDManager.SetConnectionIDLimit(params.ActiveConnectionIDLimit)
	} else {
		// use default TransportParameters
		params = &wire.TransportParameters{
			InitialMaxStreamDataBidiRemote: protocol.ByteCount(s.config.InitialStreamReceiveWindow),
			InitialMaxStreamDataBidiLocal:  protocol.ByteCount(s.config.InitialStreamReceiveWindow),
			InitialMaxStreamDataUni:        protocol.ByteCount(s.config.InitialStreamReceiveWindow),
			InitialMaxData:                 protocol.ByteCount(s.config.InitialConnectionReceiveWindow),
			MaxIdleTimeout:                 s.config.MaxIdleTimeout,
			MaxBidiStreamNum:               protocol.StreamNum(s.config.MaxIncomingStreams),
			MaxUniStreamNum:                protocol.StreamNum(s.config.MaxIncomingUniStreams),
			MaxAckDelay:                    protocol.MaxAckDelayInclGranularity,
			MaxUDPPayloadSize:              protocol.MaxPacketBufferSize,
			AckDelayExponent:               protocol.AckDelayExponent,
			DisableActiveMigration:         true,
			// For interoperability with quic-go versions before May 2023, this value must be set to a value
			// different from protocol.DefaultActiveConnectionIDLimit.
			// If set to the default value, it will be omitted from the transport parameters, which will make
			// old quic-go versions interpret it as 0, instead of the default value of 2.
			// See https://github.com/refraction-networking/uquic/pull/3806.
			ActiveConnectionIDLimit:   protocol.MaxActiveConnectionIDs,
			InitialSourceConnectionID: srcConnID,
		}
		if s.config.EnableDatagrams {
			params.MaxDatagramFrameSize = wire.MaxDatagramSize
		} else {
			params.MaxDatagramFrameSize = protocol.InvalidByteCount
		}
	}
	if s.qlogger != nil {
		s.qlogTransportParameters(params, protocol.PerspectiveClient, false)
	}
	cs := handshake.NewUCryptoSetupClient(
		destConnID,
		params,
		tlsConf,
		enable0RTT,
		s.rttStats,
		s.qlogger,
		logger,
		s.version,
		chs,
	)
	s.cryptoStreamHandler = cs
	s.cryptoStreamManager = newCryptoStreamManager(s.initialStream, s.handshakeStream, oneRTTStream)
	s.unpacker = newPacketUnpacker(cs, s.srcConnIDLen)
	s.packer = newUPacketPacker(
		newPacketPacker(srcConnID, s.connIDManager.Get, s.initialStream, s.handshakeStream, s.sentPacketHandler, s.retransmissionQueue, cs, s.framer, &s.receivedPacketHandler, s.datagramQueue, s.perspective),
		uSpec,
	)
	if len(tlsConf.ServerName) > 0 {
		s.tokenStoreKey = tlsConf.ServerName
	} else {
		s.tokenStoreKey = conn.RemoteAddr().String()
	}
	if s.config.TokenStore != nil {
		if token := s.config.TokenStore.Pop(s.tokenStoreKey); token != nil {
			s.packer.SetToken(token.data)
		}
	}
	return &wrappedConn{Conn: s}
}

// [UQUIC] clientHelloSpecForConn returns the ClientHelloSpec one connection hands to
// uTLS, and that spec's QUICTransportParametersExtension. It returns (chs, nil) if chs
// has no QUICTransportParametersExtension.
//
// Setting up a connection rewrites its transport parameters: suppression, the optional
// shuffle, and the real source connection ID in place of a zero-length
// initial_source_connection_id (PopulateFromUQUIC). Doing that on the caller's extension
// would make a QUICSpec work only once. The next dial from the same spec would carry the
// previous connection's source connection ID, which the server rejects with
// TRANSPORT_PARAMETER_ERROR. http3.Transport re-dials with one spec, so it hits this.
//
// The returned spec is a shallow copy of chs, so it shares every other extension with
// the caller; ApplyPreset copies the ones uTLS fills in per connection. Only the
// transport parameters extension is replaced: by a new extension, so no cached encoding
// is carried over, holding a copy of the parameter slice. GREASE parameters are copied
// too, since ID and Value memoize their random draws in the parameter. A parameter
// whose ID or value is already fixed (set explicitly, or pinned by calling ID, e.g.
// through QUICSpec.TransportParameterIDs) keeps it. Otherwise each connection draws its
// own.
func clientHelloSpecForConn(chs *tls.ClientHelloSpec) (*tls.ClientHelloSpec, *tls.QUICTransportParametersExtension) {
	for i, ext := range chs.Extensions {
		qtp, ok := ext.(*tls.QUICTransportParametersExtension)
		if !ok {
			continue
		}
		connQTP := &tls.QUICTransportParametersExtension{
			TransportParameters: make(tls.TransportParameters, len(qtp.TransportParameters)),
		}
		for j, tp := range qtp.TransportParameters {
			if g, ok := tp.(*tls.GREASETransportParameter); ok && g != nil {
				gc := *g
				gc.ValueOverride = slices.Clone(g.ValueOverride)
				tp = &gc
			}
			connQTP.TransportParameters[j] = tp
		}
		connCHS := *chs
		connCHS.Extensions = slices.Clone(chs.Extensions)
		connCHS.Extensions[i] = connQTP
		return &connCHS, connQTP
	}
	return chs, nil
}
