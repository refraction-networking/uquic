package handshake

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/qtls"
	"github.com/refraction-networking/uquic/internal/utils"
	"github.com/refraction-networking/uquic/internal/wire"
	"github.com/refraction-networking/uquic/logging"
	"github.com/refraction-networking/uquic/quicvarint"
	tls "github.com/refraction-networking/utls"
)

type uCryptoSetup struct {
	tlsConf *tls.Config
	conn    *tls.UQUICConn

	events []Event

	version protocol.Version

	ourParams  *wire.TransportParameters
	peerParams *wire.TransportParameters

	zeroRTTParameters *wire.TransportParameters
	allow0RTT         bool

	rttStats *utils.RTTStats

	tracer *logging.ConnectionTracer
	logger utils.Logger

	perspective protocol.Perspective

	handshakeCompleteTime time.Time

	zeroRTTOpener LongHeaderOpener // only set for the server
	zeroRTTSealer LongHeaderSealer // only set for the client

	initialOpener LongHeaderOpener
	initialSealer LongHeaderSealer

	handshakeOpener LongHeaderOpener
	handshakeSealer LongHeaderSealer

	used0RTT atomic.Bool

	aead          *updatableAEAD
	has1RTTSealer bool
	has1RTTOpener bool
}

var _ CryptoSetup = &uCryptoSetup{}

// [UQUIC]
// NewUCryptoSetupClient creates a new crypto setup for the client with UTLS
func NewUCryptoSetupClient(
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	tlsConf *tls.Config,
	enable0RTT bool,
	rttStats *utils.RTTStats,
	tracer *logging.ConnectionTracer,
	logger utils.Logger,
	version protocol.Version,
	chs *tls.ClientHelloSpec,
) CryptoSetup {
	cs := newUCryptoSetup(
		connID,
		tp,
		rttStats,
		tracer,
		logger,
		protocol.PerspectiveClient,
		version,
	)

	tlsConf = tlsConf.Clone()
	tlsConf.MinVersion = tls.VersionTLS13
	quicConf := &tls.QUICConfig{TLSConfig: tlsConf}
	qtls.SetupConfigForClient(quicConf, cs.marshalDataForSessionState, cs.handleDataFromSessionState)
	cs.tlsConf = tlsConf

	// [UQUIC]
	cs.conn = tls.UQUICClient(quicConf, tls.HelloCustom)
	if err := cs.conn.ApplyPreset(chs); err != nil {
		panic(err)
	}

	// cs.conn.SetTransportParameters(cs.ourParams.Marshal(protocol.PerspectiveClient)) // [UQUIC] doesn't require this

	return cs
}

func newUCryptoSetup(
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	rttStats *utils.RTTStats,
	tracer *logging.ConnectionTracer,
	logger utils.Logger,
	perspective protocol.Perspective,
	version protocol.Version,
) *uCryptoSetup {
	initialSealer, initialOpener := NewInitialAEAD(connID, perspective, version)
	if tracer != nil {
		tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveClient)
		tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveServer)
	}
	return &uCryptoSetup{
		initialSealer: initialSealer,
		initialOpener: initialOpener,
		aead:          newUpdatableAEAD(rttStats, tracer, logger, version),
		events:        make([]Event, 0, 16),
		ourParams:     tp,
		rttStats:      rttStats,
		tracer:        tracer,
		logger:        logger,
		perspective:   perspective,
		version:       version,
	}
}

func (h *uCryptoSetup) ChangeConnectionID(id protocol.ConnectionID) {
	initialSealer, initialOpener := NewInitialAEAD(id, h.perspective, h.version)
	h.initialSealer = initialSealer
	h.initialOpener = initialOpener
	if h.tracer != nil {
		h.tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveClient)
		h.tracer.UpdatedKeyFromTLS(protocol.EncryptionInitial, protocol.PerspectiveServer)
	}
}

func (h *uCryptoSetup) SetLargest1RTTAcked(pn protocol.PacketNumber) error {
	return h.aead.SetLargestAcked(pn)
}

func (h *uCryptoSetup) StartHandshake() error {
	err := h.conn.Start(context.WithValue(context.Background(), QUICVersionContextKey, h.version))
	if err != nil {
		return wrapError(err)
	}
	for {
		ev := h.conn.NextEvent()
		done, err := h.handleEvent(ev)
		if err != nil {
			return wrapError(err)
		}
		if done {
			break
		}
	}
	if h.perspective == protocol.PerspectiveClient {
		if h.zeroRTTSealer != nil && h.zeroRTTParameters != nil {
			h.logger.Debugf("Doing 0-RTT.")
			h.events = append(h.events, Event{Kind: EventRestoredTransportParameters, TransportParameters: h.zeroRTTParameters})
		} else {
			h.logger.Debugf("Not doing 0-RTT. Has sealer: %t, has params: %t", h.zeroRTTSealer != nil, h.zeroRTTParameters != nil)
		}
	}
	return nil
}

// Close closes the crypto setup.
// It aborts the handshake, if it is still running.
func (h *uCryptoSetup) Close() error {
	return h.conn.Close()
}

// HandleMessage handles a TLS handshake message.
// It is called by the crypto streams when a new message is available.
func (h *uCryptoSetup) HandleMessage(data []byte, encLevel protocol.EncryptionLevel) error {
	if err := h.handleMessage(data, encLevel); err != nil {
		return wrapError(err)
	}
	return nil
}

func (h *uCryptoSetup) handleMessage(data []byte, encLevel protocol.EncryptionLevel) error {
	if err := h.conn.HandleData(qtls.ToTLSEncryptionLevel(encLevel), data); err != nil {
		return err
	}
	for {
		ev := h.conn.NextEvent()
		done, err := h.handleEvent(ev)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

func (h *uCryptoSetup) handleEvent(ev tls.QUICEvent) (done bool, err error) {
	switch ev.Kind {
	case tls.QUICNoEvent:
		fmt.Printf("tls.QUICNoEvent\n")
		return true, nil
	case tls.QUICSetReadSecret:
		fmt.Printf("tls.QUICSetReadSecret\n")
		h.setReadKey(ev.Level, ev.Suite, ev.Data)
		return false, nil
	case tls.QUICSetWriteSecret:
		fmt.Printf("tls.QUICSetWriteSecret\n")
		h.setWriteKey(ev.Level, ev.Suite, ev.Data)
		return false, nil
	case tls.QUICTransportParameters:
		fmt.Printf("tls.QUICTransportParameters\n")
		return false, h.handleTransportParameters(ev.Data)
	case tls.QUICTransportParametersRequired:
		fmt.Printf("tls.QUICTransportParametersRequired\n")
		h.conn.SetTransportParameters(h.ourParams.Marshal(h.perspective))
		// [UQUIC] doesn't expect this and may fail
		return false, nil
	case tls.QUICRejectedEarlyData:
		fmt.Printf("tls.QUICRejectedEarlyData\n")
		h.rejected0RTT()
		return false, nil
	case tls.QUICWriteData:
		fmt.Printf("tls.QUICWriteData\n")
		h.writeRecord(ev.Level, ev.Data)
		return false, nil
	case tls.QUICHandshakeDone:
		fmt.Printf("tls.QUICHandshakeDone\n")
		h.handshakeComplete()
		return false, nil
	default:
		return false, fmt.Errorf("unexpected event: %d", ev.Kind)
	}
}

func (h *uCryptoSetup) NextEvent() Event {
	if len(h.events) == 0 {
		return Event{Kind: EventNoEvent}
	}
	ev := h.events[0]
	h.events = h.events[1:]
	return ev
}

func (h *uCryptoSetup) handleTransportParameters(data []byte) error {
	var tp wire.TransportParameters
	if err := tp.Unmarshal(data, h.perspective.Opposite()); err != nil {
		return err
	}
	h.peerParams = &tp
	h.events = append(h.events, Event{Kind: EventReceivedTransportParameters, TransportParameters: h.peerParams})
	return nil
}

// must be called after receiving the transport parameters
func (h *uCryptoSetup) marshalDataForSessionState(earlyData bool) []byte {
	b := make([]byte, 0, 256)
	b = quicvarint.Append(b, clientSessionStateRevision)
	b = quicvarint.Append(b, uint64(h.rttStats.SmoothedRTT().Microseconds()))
	if earlyData {
		// only save the transport parameters for 0-RTT enabled session tickets
		return h.peerParams.MarshalForSessionTicket(b)
	}
	return b
}

func (h *uCryptoSetup) handleDataFromSessionState(data []byte, earlyData bool) (allowEarlyData bool) {
	rtt, tp, err := decodeDataFromSessionState(data, earlyData)
	if err != nil {
		h.logger.Debugf("Restoring of transport parameters from session ticket failed: %s", err.Error())
		return
	}
	h.rttStats.SetInitialRTT(rtt)
	// The session ticket might have been saved from a connection that allowed 0-RTT,
	// and therefore contain transport parameters.
	// Only use them if 0-RTT is actually used on the new connection.
	if tp != nil && h.allow0RTT {
		h.zeroRTTParameters = tp
		return true
	}
	return false
}

// GetSessionTicket generates a new session ticket.
// Due to limitations in crypto/tls, it's only possible to generate a single session ticket per connection.
// It is only valid for the server.
func (h *uCryptoSetup) GetSessionTicket() ([]byte, error) {
	if err := h.conn.SendSessionTicket(tls.QUICSessionTicketOptions{
		EarlyData: h.allow0RTT,
	}); err != nil {
		// Session tickets might be disabled by tls.Config.SessionTicketsDisabled.
		// We can't check h.tlsConfig here, since the actual config might have been obtained from
		// the GetConfigForClient callback.
		// See https://github.com/golang/go/issues/62032.
		// Once that issue is resolved, this error assertion can be removed.
		if strings.Contains(err.Error(), "session ticket keys unavailable") {
			return nil, nil
		}
		return nil, err
	}
	ev := h.conn.NextEvent()
	if ev.Kind != tls.QUICWriteData || ev.Level != tls.QUICEncryptionLevelApplication {
		panic("crypto/tls bug: where's my session ticket?")
	}
	ticket := ev.Data
	if ev := h.conn.NextEvent(); ev.Kind != tls.QUICNoEvent {
		panic("crypto/tls bug: why more than one ticket?")
	}
	return ticket, nil
}

// rejected0RTT is called for the client when the server rejects 0-RTT.
func (h *uCryptoSetup) rejected0RTT() {
	h.logger.Debugf("0-RTT was rejected. Dropping 0-RTT keys.")

	had0RTTKeys := h.zeroRTTSealer != nil
	h.zeroRTTSealer = nil

	if had0RTTKeys {
		h.events = append(h.events, Event{Kind: EventDiscard0RTTKeys})
	}
}

func (h *uCryptoSetup) SetReadKey(el tls.QUICEncryptionLevel, suiteID uint16, trafficSecret []byte) {
	h.setReadKey(el, suiteID, trafficSecret)
}

func (h *uCryptoSetup) setReadKey(el tls.QUICEncryptionLevel, suiteID uint16, trafficSecret []byte) {
	suite := getCipherSuite(suiteID)
	//nolint:exhaustive // The TLS stack doesn't export Initial keys.
	switch el {
	case tls.QUICEncryptionLevelEarly:
		if h.perspective == protocol.PerspectiveClient {
			panic("Received 0-RTT read key for the client")
		}
		h.zeroRTTOpener = newLongHeaderOpener(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		h.used0RTT.Store(true)
		if h.logger.Debug() {
			h.logger.Debugf("Installed 0-RTT Read keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
		fmt.Printf("0RTT read keys: %v\n", hex.EncodeToString(trafficSecret))
	case tls.QUICEncryptionLevelHandshake:
		h.handshakeOpener = newLongHeaderOpener(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed Handshake Read keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
		fmt.Printf("handshake read keys: %v\n", hex.EncodeToString(trafficSecret))
	case tls.QUICEncryptionLevelApplication:
		h.aead.SetReadKey(suite, trafficSecret)
		h.has1RTTOpener = true
		if h.logger.Debug() {
			h.logger.Debugf("Installed 1-RTT Read keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
		fmt.Printf("application read keys: %v\n", hex.EncodeToString(trafficSecret))
	default:
		panic("unexpected read encryption level")
	}
	h.events = append(h.events, Event{Kind: EventReceivedReadKeys})
	if h.tracer != nil && h.tracer.UpdatedKeyFromTLS != nil {
		h.tracer.UpdatedKeyFromTLS(qtls.FromTLSEncryptionLevel(el), h.perspective.Opposite())
	}
}

func (h *uCryptoSetup) SetWriteKey(el tls.QUICEncryptionLevel, suiteID uint16, trafficSecret []byte) {
	h.setWriteKey(el, suiteID, trafficSecret)
}
func (h *uCryptoSetup) setWriteKey(el tls.QUICEncryptionLevel, suiteID uint16, trafficSecret []byte) {
	suite := getCipherSuite(suiteID)
	//nolint:exhaustive // The TLS stack doesn't export Initial keys.
	switch el {
	case tls.QUICEncryptionLevelEarly:
		if h.perspective == protocol.PerspectiveServer {
			panic("Received 0-RTT write key for the server")
		}
		h.zeroRTTSealer = newLongHeaderSealer(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed 0-RTT Write keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
		if h.tracer != nil && h.tracer.UpdatedKeyFromTLS != nil {
			h.tracer.UpdatedKeyFromTLS(protocol.Encryption0RTT, h.perspective)
		}
		// don't set used0RTT here. 0-RTT might still get rejected.
		fmt.Printf("0RTT write keys: %v\n", hex.EncodeToString(trafficSecret))
		return
	case tls.QUICEncryptionLevelHandshake:
		h.handshakeSealer = newLongHeaderSealer(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed Handshake Write keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
		fmt.Printf("handshake write keys: %v\n", hex.EncodeToString(trafficSecret))
	case tls.QUICEncryptionLevelApplication:
		h.aead.SetWriteKey(suite, trafficSecret)
		h.has1RTTSealer = true
		if h.logger.Debug() {
			h.logger.Debugf("Installed 1-RTT Write keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
		if h.zeroRTTSealer != nil {
			// Once we receive handshake keys, we know that 0-RTT was not rejected.
			h.used0RTT.Store(true)
			h.zeroRTTSealer = nil
			h.logger.Debugf("Dropping 0-RTT keys.")
			if h.tracer != nil && h.tracer.DroppedEncryptionLevel != nil {
				h.tracer.DroppedEncryptionLevel(protocol.Encryption0RTT)
			}
		}
		fmt.Printf("application write keys: %v\n", hex.EncodeToString(trafficSecret))
	default:
		panic("unexpected write encryption level")
	}
	if h.tracer != nil && h.tracer.UpdatedKeyFromTLS != nil {
		h.tracer.UpdatedKeyFromTLS(qtls.FromTLSEncryptionLevel(el), h.perspective)
	}
}

// writeRecord is called when TLS writes data
func (h *uCryptoSetup) writeRecord(encLevel tls.QUICEncryptionLevel, p []byte) {
	//nolint:exhaustive // handshake records can only be written for Initial and Handshake.
	switch encLevel {
	case tls.QUICEncryptionLevelInitial:
		h.events = append(h.events, Event{Kind: EventWriteInitialData, Data: p})
	case tls.QUICEncryptionLevelHandshake:
		h.events = append(h.events, Event{Kind: EventWriteHandshakeData, Data: p})
	case tls.QUICEncryptionLevelApplication:
		panic("unexpected write")
	default:
		panic(fmt.Sprintf("unexpected write encryption level: %s", encLevel))
	}
}

func (h *uCryptoSetup) DiscardInitialKeys() {
	dropped := h.initialOpener != nil
	h.initialOpener = nil
	h.initialSealer = nil
	if dropped {
		h.logger.Debugf("Dropping Initial keys.")
	}
}

func (h *uCryptoSetup) HandshakeComplete() {
	h.handshakeComplete()
}

func (h *uCryptoSetup) handshakeComplete() {
	h.handshakeCompleteTime = time.Now()
	h.events = append(h.events, Event{Kind: EventHandshakeComplete})
}

func (h *uCryptoSetup) SetHandshakeConfirmed() {
	h.aead.SetHandshakeConfirmed()
	// drop Handshake keys
	var dropped bool
	if h.handshakeOpener != nil {
		h.handshakeOpener = nil
		h.handshakeSealer = nil
		dropped = true
	}
	if dropped {
		h.logger.Debugf("Dropping Handshake keys.")
	}
}

func (h *uCryptoSetup) GetInitialSealer() (LongHeaderSealer, error) {
	if h.initialSealer == nil {
		return nil, ErrKeysDropped
	}
	return h.initialSealer, nil
}

func (h *uCryptoSetup) Get0RTTSealer() (LongHeaderSealer, error) {
	if h.zeroRTTSealer == nil {
		return nil, ErrKeysDropped
	}
	return h.zeroRTTSealer, nil
}

func (h *uCryptoSetup) GetHandshakeSealer() (LongHeaderSealer, error) {
	if h.handshakeSealer == nil {
		if h.initialSealer == nil {
			return nil, ErrKeysDropped
		}
		return nil, ErrKeysNotYetAvailable
	}
	return h.handshakeSealer, nil
}

func (h *uCryptoSetup) Get1RTTSealer() (ShortHeaderSealer, error) {
	if !h.has1RTTSealer {
		return nil, ErrKeysNotYetAvailable
	}
	return h.aead, nil
}

func (h *uCryptoSetup) GetInitialOpener() (LongHeaderOpener, error) {
	if h.initialOpener == nil {
		return nil, ErrKeysDropped
	}
	return h.initialOpener, nil
}

func (h *uCryptoSetup) Get0RTTOpener() (LongHeaderOpener, error) {
	if h.zeroRTTOpener == nil {
		if h.initialOpener != nil {
			return nil, ErrKeysNotYetAvailable
		}
		// if the initial opener is also not available, the keys were already dropped
		return nil, ErrKeysDropped
	}
	return h.zeroRTTOpener, nil
}

func (h *uCryptoSetup) GetHandshakeOpener() (LongHeaderOpener, error) {
	if h.handshakeOpener == nil {
		if h.initialOpener != nil {
			return nil, ErrKeysNotYetAvailable
		}
		// if the initial opener is also not available, the keys were already dropped
		return nil, ErrKeysDropped
	}
	return h.handshakeOpener, nil
}

func (h *uCryptoSetup) Get1RTTOpener() (ShortHeaderOpener, error) {
	if h.zeroRTTOpener != nil && time.Since(h.handshakeCompleteTime) > 3*h.rttStats.PTO(true) {
		h.zeroRTTOpener = nil
		h.logger.Debugf("Dropping 0-RTT keys.")
		if h.tracer != nil {
			h.tracer.DroppedEncryptionLevel(protocol.Encryption0RTT)
		}
	}

	if !h.has1RTTOpener {
		return nil, ErrKeysNotYetAvailable
	}
	return h.aead, nil
}

func (h *uCryptoSetup) ConnectionState() ConnectionState {
	return ConnectionState{
		ConnectionState: h.conn.ConnectionState(),
		Used0RTT:        h.used0RTT.Load(),
	}
}
