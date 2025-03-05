package quic

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/refraction-networking/uquic/internal/ackhandler"
	"github.com/refraction-networking/uquic/internal/handshake"
	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/qerr"
	"github.com/refraction-networking/uquic/internal/utils"
	"github.com/refraction-networking/uquic/internal/wire"
	"github.com/refraction-networking/uquic/logging"
	tls "github.com/refraction-networking/utls"
)

type SameCIDGen struct {
	id []byte
}

func (s *SameCIDGen) GenerateConnectionID() (ConnectionID, error) {
	return ConnectionIDFromBytes(s.id), nil
}

func (s *SameCIDGen) ConnectionIDLen() int {
	return len(s.id)
}

//	func (t *UTransport) DialOscur0(ctx context.Context, addr net.Addr, tlsConf *tls.Config, conf *Config) (Connection, error) {
//		return t.dialOscur0(ctx, addr, "", tlsConf, conf, false)
//	}
// var srcCID = ConnectionIDFromBytes([]uint8{1, 2, 3, 4})
// var dstCID = ConnectionIDFromBytes([]uint8{5, 6, 7, 8})

func (t *UTransport) dialOscur0(ctx context.Context, addr net.Addr, host string, tlsConf *tls.Config, conf *Config, use0RTT bool, oscur0Conf *Oscur0Config) (EarlyConnection, error) {
	if err := validateConfig(conf); err != nil {
		return nil, err
	}
	conf = populateConfig(conf)

	// [UQUIC]
	// Override the default connection ID generator if the user has specified a length in QUICSpec.
	if t.QUICSpec != nil {
		if t.QUICSpec.InitialPacketSpec.SrcConnIDLength != 0 {
			t.ConnectionIDGenerator = &protocol.DefaultConnectionIDGenerator{ConnLen: t.QUICSpec.InitialPacketSpec.SrcConnIDLength}
		} else {
			t.ConnectionIDGenerator = &protocol.ExpEmptyConnectionIDGenerator{}
		}
	}
	// [/UQUIC]

	t.ConnectionIDGenerator = &SameCIDGen{id: oscur0Conf.ClientConnID}

	if err := t.init(t.isSingleUse); err != nil {
		return nil, err
	}
	var onClose func()
	if t.isSingleUse {
		onClose = func() { t.Close() }
	}
	tlsConf = tlsConf.Clone()
	tlsConf.MinVersion = tls.VersionTLS13
	setTLSConfigServerName(tlsConf, addr, host)
	return udialOscur0(ctx, newSendConn(t.conn, addr, packetInfo{}, utils.DefaultLogger), t.connIDGenerator, t.handlerMap, tlsConf, conf, onClose, use0RTT, t.QUICSpec, oscur0Conf)
}

func udialOscur0(
	ctx context.Context,
	conn sendConn,
	connIDGenerator ConnectionIDGenerator,
	packetHandlers packetHandlerManager,
	tlsConf *tls.Config,
	config *Config,
	onClose func(),
	use0RTT bool,
	uSpec *QUICSpec, // [UQUIC]
	oscur0Conf *Oscur0Config,
) (quicConn, error) {
	c, err := newClient(conn, connIDGenerator, config, tlsConf, onClose, use0RTT)
	if err != nil {
		return nil, err
	}
	c.packetHandlers = packetHandlers

	c.destConnID = ConnectionIDFromBytes(oscur0Conf.ServerConnID)
	c.srcConnID = ConnectionIDFromBytes(oscur0Conf.ClientConnID)

	// // [UQUIC]
	// if uSpec.InitialPacketSpec.DestConnIDLength > 0 {
	// 	destConnID, err := generateConnectionIDForInitialWithLength(uSpec.InitialPacketSpec.DestConnIDLength)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	c.destConnID = destConnID
	// }
	// c.initialPacketNumber = protocol.PacketNumber(uSpec.InitialPacketSpec.InitPacketNumber)
	// // [/UQUIC]

	c.tracingID = nextConnTracingID()
	if c.config.Tracer != nil {
		c.tracer = c.config.Tracer(context.WithValue(ctx, ConnectionTracingKey, c.tracingID), protocol.PerspectiveClient, c.destConnID)
	}
	if c.tracer != nil {
		c.tracer.StartedConnection(c.sendConn.LocalAddr(), c.sendConn.RemoteAddr(), c.srcConnID, c.destConnID)
	}

	// [UQUIC]
	uc := &uClient{
		client: c,
		uSpec:  uSpec,
	}
	// [/UQUIC]

	if err := uc.dialOscur0(ctx, oscur0Conf); err != nil {
		return nil, err
	}
	return uc.conn, nil
}

func (c *uClient) dialOscur0(ctx context.Context, oscur0Conf *Oscur0Config) error {
	c.logger.Infof("Starting new uQUIC connection to %s (%s -> %s), source connection ID %s, destination connection ID %s, version %s", c.tlsConf.ServerName, c.sendConn.LocalAddr(), c.sendConn.RemoteAddr(), c.srcConnID, c.destConnID, c.version)

	// [UQUIC]
	if c.uSpec.ClientHelloSpec == nil {
		c.conn = newClientConnection(
			c.sendConn,
			c.packetHandlers,
			c.destConnID,
			c.srcConnID,
			c.connIDGenerator,
			c.config,
			c.tlsConf,
			c.initialPacketNumber,
			c.use0RTT,
			c.hasNegotiatedVersion,
			c.tracer,
			c.tracingID,
			c.logger,
			c.version,
		)
	} else {
		// [UQUIC]: use custom version of the connection
		c.conn = newUClientConnectionOscur0(
			c.sendConn,
			c.packetHandlers,
			c.destConnID,
			c.srcConnID,
			c.connIDGenerator,
			c.config,
			c.tlsConf,
			c.initialPacketNumber,
			c.use0RTT,
			c.hasNegotiatedVersion,
			c.tracer,
			c.tracingID,
			c.logger,
			c.version,
			c.uSpec,
		)
	}
	// [/UQUIC]

	c.packetHandlers.Add(c.srcConnID, c.conn)

	c.client.conn.(*connection).origDestConnID = c.destConnID
	c.client.conn.(*connection).handshakeDestConnID = c.destConnID

	c.client.conn.(*connection).handleTransportParameters(&wire.TransportParameters{
		InitialMaxStreamDataBidiLocal:   524288,
		InitialMaxStreamDataBidiRemote:  524288,
		InitialMaxStreamDataUni:         524288,
		InitialMaxData:                  786432,
		MaxAckDelay:                     protocol.MaxAckDelayInclGranularity,
		InitialSourceConnectionID:       c.client.conn.(*connection).handshakeDestConnID,
		OriginalDestinationConnectionID: c.client.conn.(*connection).origDestConnID,
		AckDelayExponent:                3,
		DisableActiveMigration:          true,
		MaxUDPPayloadSize:               1452,
		MaxUniStreamNum:                 100,
		MaxBidiStreamNum:                100,
		MaxIdleTimeout:                  protocol.DefaultIdleTimeout,
		PreferredAddress:                nil,
		RetrySourceConnectionID:         nil,
		StatelessResetToken:             &protocol.StatelessResetToken{40, 46, 38, 234, 106, 208, 207, 28, 246, 176, 190, 31, 90, 150, 17, 222},
		ActiveConnectionIDLimit:         1,
		MaxDatagramFrameSize:            -1,
		ClientOverride:                  nil,
	})

	c.client.conn.(*connection).cryptoStreamHandler.SetReadKey(tls.QUICEncryptionLevelApplication, tls.TLS_CHACHA20_POLY1305_SHA256, oscur0Conf.ReadKey)
	c.client.conn.(*connection).cryptoStreamHandler.SetWriteKey(tls.QUICEncryptionLevelApplication, tls.TLS_CHACHA20_POLY1305_SHA256, oscur0Conf.WriteKey)
	c.client.conn.(*connection).cryptoStreamHandler.HandshakeComplete()
	c.client.conn.(*connection).handleHandshakeComplete()

	errorChan := make(chan error, 1)
	recreateChan := make(chan errCloseForRecreating)
	go func() {
		err := c.conn.runOscur0()
		var recreateErr *errCloseForRecreating
		if errors.As(err, &recreateErr) {
			recreateChan <- *recreateErr
			return
		}
		if c.onClose != nil {
			c.onClose()
		}
		errorChan <- err // returns as soon as the connection is closed
	}()

	// only set when we're using 0-RTT
	// Otherwise, earlyConnChan will be nil. Receiving from a nil chan blocks forever.
	var earlyConnChan <-chan struct{}
	if c.use0RTT {
		earlyConnChan = c.conn.earlyConnReady()
	}

	select {
	case <-ctx.Done():
		c.conn.destroy(nil)
		return context.Cause(ctx)
	case err := <-errorChan:
		return err
	case recreateErr := <-recreateChan:
		c.initialPacketNumber = recreateErr.nextPacketNumber
		c.version = recreateErr.nextVersion
		c.hasNegotiatedVersion = true
		return c.dial(ctx)
	case <-earlyConnChan:
		// ready to send 0-RTT data
		return nil
	case <-c.conn.HandshakeComplete():
		// handshake successfully completed
		return nil
	}
}

// [UQUIC]
var newUClientConnectionOscur0 = func(
	conn sendConn,
	runner connRunner,
	destConnID protocol.ConnectionID,
	srcConnID protocol.ConnectionID,
	connIDGenerator ConnectionIDGenerator,
	conf *Config,
	tlsConf *tls.Config,
	initialPacketNumber protocol.PacketNumber,
	enable0RTT bool,
	hasNegotiatedVersion bool,
	tracer *logging.ConnectionTracer,
	tracingID uint64,
	logger utils.Logger,
	v protocol.Version,
	uSpec *QUICSpec, // [UQUIC]
) *connection {
	s := &connection{
		conn:                conn,
		config:              conf,
		origDestConnID:      destConnID,
		handshakeDestConnID: destConnID,
		srcConnIDLen:        srcConnID.Len(),
		perspective:         protocol.PerspectiveClient,
		logID:               destConnID.String(),
		logger:              logger,
		tracer:              tracer,
		versionNegotiated:   hasNegotiatedVersion,
		version:             v,
	}
	s.connIDManager = newConnIDManager(
		destConnID,
		func(token protocol.StatelessResetToken) { runner.AddResetToken(token, s) },
		runner.RemoveResetToken,
		s.queueControlFrame,
	)

	s.connIDGenerator = newConnIDGenerator(
		srcConnID,
		nil,
		func(connID protocol.ConnectionID) { runner.Add(connID, s) },
		runner.GetStatelessResetToken,
		runner.Remove,
		runner.Retire,
		runner.ReplaceWithClosed,
		s.queueControlFrame,
		connIDGenerator,
	)
	s.preSetup()
	s.ctx, s.ctxCancel = context.WithCancelCause(context.WithValue(context.Background(), ConnectionTracingKey, tracingID))
	s.sentPacketHandler, s.receivedPacketHandler = ackhandler.NewUAckHandler(
		initialPacketNumber,
		getMaxPacketSize(s.conn.RemoteAddr()),
		s.rttStats,
		false, // has no effect
		s.conn.capabilities().ECN,
		s.perspective,
		s.tracer,
		s.logger,
	)
	// [UQUIC]
	if uSpec.InitialPacketSpec.InitPacketNumberLength != 0 {
		ackhandler.SetInitialPacketNumberLength(s.sentPacketHandler, uSpec.InitialPacketSpec.InitPacketNumberLength)
	}

	s.mtuDiscoverer = newMTUDiscoverer(s.rttStats, getMaxPacketSize(s.conn.RemoteAddr()), s.sentPacketHandler.SetMaxDatagramSize)
	oneRTTStream := newCryptoStream()

	var params *wire.TransportParameters

	if uSpec.ClientHelloSpec != nil {
		// iterate over all Extensions to set the TransportParameters
		var tpSet bool
	FOR_EACH_TLS_EXTENSION:
		for _, ext := range uSpec.ClientHelloSpec.Extensions {
			switch ext := ext.(type) {
			case *tls.QUICTransportParametersExtension:
				params = &wire.TransportParameters{
					InitialSourceConnectionID: srcConnID,
				}
				params.PopulateFromUQUIC(ext.TransportParameters)
				s.connIDManager.SetConnectionIDLimit(params.ActiveConnectionIDLimit)
				tpSet = true
				break FOR_EACH_TLS_EXTENSION
			default:
				continue FOR_EACH_TLS_EXTENSION
			}
		}
		if !tpSet {
			panic("applied ClientHelloSpec must contain a QUICTransportParametersExtension to proceed")
		}
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
			AckDelayExponent:               protocol.AckDelayExponent,
			DisableActiveMigration:         true,
			// For interoperability with quic-go versions before May 2023, this value must be set to a value
			// different from protocol.DefaultActiveConnectionIDLimit.
			// If set to the default value, it will be omitted from the transport parameters, which will make
			// old quic-go versions interpret it as 0, instead of the default value of 2.
			// See https://github.com/refraction-networking/uquic/pull/3806.
			ActiveConnectionIDLimit:   1,
			InitialSourceConnectionID: srcConnID,
		}
		if s.config.EnableDatagrams {
			params.MaxDatagramFrameSize = wire.MaxDatagramSize
		} else {
			params.MaxDatagramFrameSize = protocol.InvalidByteCount
		}
	}
	if s.tracer != nil && s.tracer.SentTransportParameters != nil {
		s.tracer.SentTransportParameters(params)
	}
	cs := handshake.NewUCryptoSetupClient(
		destConnID,
		params,
		tlsConf,
		enable0RTT,
		s.rttStats,
		tracer,
		logger,
		s.version,
		uSpec.ClientHelloSpec,
	)
	s.cryptoStreamHandler = cs
	s.cryptoStreamManager = newCryptoStreamManager(cs, s.initialStream, s.handshakeStream, oneRTTStream)
	s.unpacker = newPacketUnpacker(cs, s.srcConnIDLen)
	s.packer = newUPacketPacker(
		newPacketPacker(srcConnID, s.connIDManager.Get, s.initialStream, s.handshakeStream, s.sentPacketHandler, s.retransmissionQueue, cs, s.framer, s.receivedPacketHandler, s.datagramQueue, s.perspective),
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
	fmt.Printf("hi\n")
	return s
}

func (s *connection) runOscur0() error {
	var closeErr closeError
	defer func() {
		s.ctxCancel(closeErr.err)
	}()

	s.timer = *newTimer()

	// if err := s.cryptoStreamHandler.StartHandshake(); err != nil {
	// 	return err
	// }
	if err := s.handleHandshakeEvents(); err != nil {
		return err
	}
	go func() {
		if err := s.sendQueue.Run(); err != nil {
			s.destroyImpl(err)
		}
	}()

	if s.perspective == protocol.PerspectiveClient {
		s.scheduleSending() // so the ClientHello actually gets sent
	}

	var sendQueueAvailable <-chan struct{}

runLoop:
	for {
		if s.framer.QueuedTooManyControlFrames() {
			s.closeLocal(&qerr.TransportError{ErrorCode: InternalError})
		}
		// Close immediately if requested
		select {
		case closeErr = <-s.closeChan:
			break runLoop
		default:
		}

		s.maybeResetTimer()

		var processedUndecryptablePacket bool
		if len(s.undecryptablePacketsToProcess) > 0 {
			queue := s.undecryptablePacketsToProcess
			s.undecryptablePacketsToProcess = nil
			for _, p := range queue {
				if processed := s.handlePacketImpl(p); processed {
					processedUndecryptablePacket = true
				}
				// Don't set timers and send packets if the packet made us close the connection.
				select {
				case closeErr = <-s.closeChan:
					break runLoop
				default:
				}
			}
		}
		// If we processed any undecryptable packets, jump to the resetting of the timers directly.
		if !processedUndecryptablePacket {
			select {
			case closeErr = <-s.closeChan:
				break runLoop
			case <-s.timer.Chan():
				s.timer.SetRead()
				// We do all the interesting stuff after the switch statement, so
				// nothing to see here.
			case <-s.sendingScheduled:
				// We do all the interesting stuff after the switch statement, so
				// nothing to see here.
			case <-sendQueueAvailable:
			case firstPacket := <-s.receivedPackets:
				wasProcessed := s.handlePacketImpl(firstPacket)
				// Don't set timers and send packets if the packet made us close the connection.
				select {
				case closeErr = <-s.closeChan:
					break runLoop
				default:
				}
				if s.handshakeComplete {
					// Now process all packets in the receivedPackets channel.
					// Limit the number of packets to the length of the receivedPackets channel,
					// so we eventually get a chance to send out an ACK when receiving a lot of packets.
					numPackets := len(s.receivedPackets)
				receiveLoop:
					for i := 0; i < numPackets; i++ {
						select {
						case p := <-s.receivedPackets:
							if processed := s.handlePacketImpl(p); processed {
								wasProcessed = true
							}
							select {
							case closeErr = <-s.closeChan:
								break runLoop
							default:
							}
						default:
							break receiveLoop
						}
					}
				}
				// Only reset the timers if this packet was actually processed.
				// This avoids modifying any state when handling undecryptable packets,
				// which could be injected by an attacker.
				if !wasProcessed {
					continue
				}
			}
		}

		now := time.Now()
		if timeout := s.sentPacketHandler.GetLossDetectionTimeout(); !timeout.IsZero() && timeout.Before(now) {
			// This could cause packets to be retransmitted.
			// Check it before trying to send packets.
			if err := s.sentPacketHandler.OnLossDetectionTimeout(); err != nil {
				s.closeLocal(err)
			}
		}

		// if keepAliveTime := s.nextKeepAliveTime(); !keepAliveTime.IsZero() && !now.Before(keepAliveTime) {
		// 	// send a PING frame since there is no activity in the connection
		// 	s.logger.Debugf("Sending a keep-alive PING to keep the connection alive.")
		// 	s.framer.QueueControlFrame(&wire.PingFrame{})
		// 	s.keepAlivePingSent = true
		// } else if !s.handshakeComplete && now.Sub(s.creationTime) >= s.config.handshakeTimeout() {
		// 	s.destroyImpl(qerr.ErrHandshakeTimeout)
		// 	continue
		// } else {
		// 	idleTimeoutStartTime := s.idleTimeoutStartTime()
		// 	if (!s.handshakeComplete && now.Sub(idleTimeoutStartTime) >= s.config.HandshakeIdleTimeout) ||
		// 		(s.handshakeComplete && now.After(s.nextIdleTimeoutTime())) {
		// 		s.destroyImpl(qerr.ErrIdleTimeout)
		// 		continue
		// 	}
		// }

		if s.sendQueue.WouldBlock() {
			// The send queue is still busy sending out packets.
			// Wait until there's space to enqueue new packets.
			sendQueueAvailable = s.sendQueue.Available()
			continue
		}
		if err := s.triggerSending(now); err != nil {
			s.closeLocal(err)
		}
		if s.sendQueue.WouldBlock() {
			sendQueueAvailable = s.sendQueue.Available()
		} else {
			sendQueueAvailable = nil
		}
	}

	s.cryptoStreamHandler.Close()
	s.sendQueue.Close() // close the send queue before sending the CONNECTION_CLOSE
	s.handleCloseError(&closeErr)
	if s.tracer != nil && s.tracer.Close != nil {
		if e := (&errCloseForRecreating{}); !errors.As(closeErr.err, &e) {
			s.tracer.Close()
		}
	}
	s.logger.Infof("Connection %s closed.", s.logID)
	s.timer.Stop()
	return closeErr.err
}

// func (l *EarlyListener) Oscur0Accept() (quicConn, error) {

// 	return l.baseServer.Oscur0Accept(&net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 6667}, srcCID, dstCID)
// }

func (s *baseServer) Oscur0Accept(remoteAddr net.Addr, oscur0Conf *Oscur0Config) (quicConn, error) {
	SrcConnectionID := ConnectionIDFromBytes(oscur0Conf.ClientConnID)
	DestConnectionID := ConnectionIDFromBytes(oscur0Conf.ServerConnID)

	// if len(hdr.Token) == 0 && hdr.DestConnectionID.Len() < protocol.MinConnectionIDLenInitial {
	// 	if s.tracer != nil && s.tracer.DroppedPacket != nil {
	// 		s.tracer.DroppedPacket(p.remoteAddr, logging.PacketTypeInitial, p.Size(), logging.PacketDropUnexpectedPacket)
	// 	}
	// 	p.buffer.Release()
	// 	return errors.New("too short connection ID")
	// }

	// // The server queues packets for a while, and we might already have established a connection by now.
	// // This results in a second check in the connection map.
	// // That's ok since it's not the hot path (it's only taken by some Initial and 0-RTT packets).
	// if handler, ok := s.connHandler.Get(hdr.DestConnectionID); ok {
	// 	handler.handlePacket(p)
	// 	return nil
	// }

	// if len(hdr.Token) > 0 {
	// 	tok, err := s.tokenGenerator.DecodeToken(hdr.Token)
	// 	if err == nil {
	// 		if tok.IsRetryToken {
	// 			origDestConnID = tok.OriginalDestConnectionID
	// 			retrySrcConnID = &tok.RetrySrcConnectionID
	// 		}
	// 		token = tok
	// 	}
	// }
	// if token != nil {
	// 	clientAddrVerified = s.validateToken(token, p.remoteAddr)
	// 	if !clientAddrVerified {
	// 		// For invalid and expired non-retry tokens, we don't send an INVALID_TOKEN error.
	// 		// We just ignore them, and act as if there was no token on this packet at all.
	// 		// This also means we might send a Retry later.
	// 		if !token.IsRetryToken {
	// 			token = nil
	// 		} else {
	// 			// For Retry tokens, we send an INVALID_ERROR if
	// 			// * the token is too old, or
	// 			// * the token is invalid, in case of a retry token.
	// 			select {
	// 			case s.invalidTokenQueue <- rejectedPacket{receivedPacket: p, hdr: hdr}:
	// 			default:
	// 				// drop packet if we can't send out the  INVALID_TOKEN packets fast enough
	// 				p.buffer.Release()
	// 			}
	// 			return nil
	// 		}
	// 	}
	// }

	// if token == nil && s.verifySourceAddress != nil && s.verifySourceAddress(p.remoteAddr) {
	// 	// Retry invalidates all 0-RTT packets sent.
	// 	delete(s.zeroRTTQueues, hdr.DestConnectionID)
	// 	select {
	// 	case s.retryQueue <- rejectedPacket{receivedPacket: p, hdr: hdr}:
	// 	default:
	// 		// drop packet if we can't send out Retry packets fast enough
	// 		p.buffer.Release()
	// 	}
	// 	return nil
	// }

	config := s.config

	var conn quicConn
	tracingID := nextConnTracingID()

	// s.connIDGenerator = &SameCIDGen{}
	// connID, err := s.connIDGenerator.GenerateConnectionID()
	// if err != nil {
	// 	return nil, err
	// }
	// s.logger.Debugf("Changing connection ID to %s.", connID)

	var tracer *logging.ConnectionTracer
	if config.Tracer != nil {
		// // Use the same connection ID that is passed to the client's GetLogWriter callback.
		// connID := hdr.DestConnectionID
		// if origDestConnID.Len() > 0 {
		// 	connID = origDestConnID
		// }
		tracer = config.Tracer(context.WithValue(context.Background(), ConnectionTracingKey, tracingID), protocol.PerspectiveServer, SrcConnectionID)
	}
	conn = s.newConn(
		newSendConn(s.conn, remoteAddr, packetInfo{}, s.logger),
		s.connHandler,
		DestConnectionID,
		&SrcConnectionID,
		DestConnectionID,
		SrcConnectionID,
		SrcConnectionID,
		s.connIDGenerator,
		s.connHandler.GetStatelessResetToken(SrcConnectionID),
		config,
		s.tlsConf,
		s.tokenGenerator,
		true,
		tracer,
		tracingID,
		s.logger,
		Version1,
	)
	// Adding the connection will fail if the client's chosen Destination Connection ID is already in use.
	// This is very unlikely: Even if an attacker chooses a connection ID that's already in use,
	// under normal circumstances the packet would just be routed to that connection.
	// The only time this collision will occur if we receive the two Initial packets at the same time.
	if added := s.connHandler.AddWithConnID(DestConnectionID, SrcConnectionID, conn); !added {
		delete(s.zeroRTTQueues, DestConnectionID)
		conn.closeWithTransportError(qerr.ConnectionRefused)
		return nil, fmt.Errorf("dst cid already in use")
	}
	// Pass queued 0-RTT to the newly established connection.
	if q, ok := s.zeroRTTQueues[DestConnectionID]; ok {
		for _, p := range q.packets {
			conn.handlePacket(p)
		}
		delete(s.zeroRTTQueues, DestConnectionID)
	}

	conn.(*connection).handleTransportParameters(&wire.TransportParameters{
		InitialMaxStreamDataBidiLocal:  protocol.DefaultMaxReceiveStreamFlowControlWindow,
		InitialMaxStreamDataBidiRemote: protocol.DefaultMaxReceiveStreamFlowControlWindow,
		InitialMaxStreamDataUni:        protocol.DefaultMaxReceiveStreamFlowControlWindow,
		InitialMaxData:                 protocol.DefaultMaxReceiveConnectionFlowControlWindow,
		MaxAckDelay:                    protocol.MaxAckDelayInclGranularity,
		AckDelayExponent:               protocol.AckDelayExponent,
		DisableActiveMigration:         true,
		MaxUDPPayloadSize:              protocol.MaxByteCount,
		MaxUniStreamNum:                protocol.DefaultMaxIncomingUniStreams,
		MaxBidiStreamNum:               protocol.DefaultMaxIncomingStreams,
		MaxIdleTimeout:                 protocol.DefaultIdleTimeout,
		InitialSourceConnectionID:      SrcConnectionID,
		ActiveConnectionIDLimit:        1,
		MaxDatagramFrameSize:           1200,
	})

	conn.(*connection).cryptoStreamHandler.SetReadKey(tls.QUICEncryptionLevelApplication, tls.TLS_CHACHA20_POLY1305_SHA256, oscur0Conf.WriteKey)
	conn.(*connection).cryptoStreamHandler.SetWriteKey(tls.QUICEncryptionLevelApplication, tls.TLS_CHACHA20_POLY1305_SHA256, oscur0Conf.ReadKey)
	conn.(*connection).cryptoStreamHandler.HandshakeComplete()
	conn.(*connection).handshakeComplete = true
	conn.(*connection).handleHandshakeComplete()

	go conn.runOscur0()

	chRand := [32]byte{}
	_, err := fmt.Printf("%s %x %x\n", "CLIENT_TRAFFIC_SECRET_0", chRand, oscur0Conf.ReadKey)
	if err != nil {
		panic(err)
	}

	_, err = fmt.Printf("%s %x %x\n", "SERVER_TRAFFIC_SECRET_0", chRand, oscur0Conf.WriteKey)
	if err != nil {
		panic(err)
	}

	return conn, nil
}
