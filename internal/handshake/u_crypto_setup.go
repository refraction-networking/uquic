package handshake

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
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
	conn    *qtls.UQUICConn

	events []Event

	version protocol.VersionNumber

	ourParams  *wire.TransportParameters
	peerParams *wire.TransportParameters

	zeroRTTParameters *wire.TransportParameters
	allow0RTT         bool

	rttStats *utils.RTTStats

	tracer logging.ConnectionTracer
	logger utils.Logger

	perspective protocol.Perspective

	mutex sync.Mutex // protects all members below

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
	tracer logging.ConnectionTracer,
	logger utils.Logger,
	version protocol.VersionNumber,
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
	quicConf := &qtls.QUICConfig{TLSConfig: tlsConf}
	qtls.SetupConfigForClient(quicConf, cs.marshalDataForSessionState, cs.handleDataFromSessionState)
	cs.tlsConf = tlsConf

	cs.conn = qtls.UQUICClient(quicConf, chs)
	// cs.conn.SetTransportParameters(cs.ourParams.Marshal(protocol.PerspectiveClient)) // [UQUIC] doesn't require this

	return cs
}

func newUCryptoSetup(
	connID protocol.ConnectionID,
	tp *wire.TransportParameters,
	rttStats *utils.RTTStats,
	tracer logging.ConnectionTracer,
	logger utils.Logger,
	perspective protocol.Perspective,
	version protocol.VersionNumber,
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

func (h *uCryptoSetup) handleEvent(ev qtls.QUICEvent) (done bool, err error) {
	switch ev.Kind {
	case qtls.QUICNoEvent:
		return true, nil
	case qtls.QUICSetReadSecret:
		h.SetReadKey(ev.Level, ev.Suite, ev.Data)
		return false, nil
	case qtls.QUICSetWriteSecret:
		h.SetWriteKey(ev.Level, ev.Suite, ev.Data)
		return false, nil
	case qtls.QUICTransportParameters:
		return false, h.handleTransportParameters(ev.Data)
	case qtls.QUICTransportParametersRequired:
		h.conn.SetTransportParameters(h.ourParams.Marshal(h.perspective))
		// [UQUIC] doesn't expect this and may fail
		return false, nil
	case qtls.QUICRejectedEarlyData:
		h.rejected0RTT()
		return false, nil
	case qtls.QUICWriteData:
		h.WriteRecord(ev.Level, ev.Data)
		return false, nil
	case qtls.QUICHandshakeDone:
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
func (h *uCryptoSetup) marshalDataForSessionState() []byte {
	b := make([]byte, 0, 256)
	b = quicvarint.Append(b, clientSessionStateRevision)
	b = quicvarint.Append(b, uint64(h.rttStats.SmoothedRTT().Microseconds()))
	return h.peerParams.MarshalForSessionTicket(b)
}

func (h *uCryptoSetup) handleDataFromSessionState(data []byte) {
	tp, err := h.handleDataFromSessionStateImpl(data)
	if err != nil {
		h.logger.Debugf("Restoring of transport parameters from session ticket failed: %s", err.Error())
		return
	}
	h.zeroRTTParameters = tp
}

func (h *uCryptoSetup) handleDataFromSessionStateImpl(data []byte) (*wire.TransportParameters, error) {
	r := bytes.NewReader(data)
	ver, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	if ver != clientSessionStateRevision {
		return nil, fmt.Errorf("mismatching version. Got %d, expected %d", ver, clientSessionStateRevision)
	}
	rtt, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	h.rttStats.SetInitialRTT(time.Duration(rtt) * time.Microsecond)
	var tp wire.TransportParameters
	if err := tp.UnmarshalFromSessionTicket(r); err != nil {
		return nil, err
	}
	return &tp, nil
}

// GetSessionTicket generates a new session ticket.
// Due to limitations in crypto/tls, it's only possible to generate a single session ticket per connection.
// It is only valid for the server.
func (h *uCryptoSetup) GetSessionTicket() ([]byte, error) {
	if err := qtls.SendSessionTicket(h.conn, h.allow0RTT); err != nil {
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
	if ev.Kind != qtls.QUICWriteData || ev.Level != qtls.QUICEncryptionLevelApplication {
		panic("crypto/tls bug: where's my session ticket?")
	}
	ticket := ev.Data
	if ev := h.conn.NextEvent(); ev.Kind != qtls.QUICNoEvent {
		panic("crypto/tls bug: why more than one ticket?")
	}
	return ticket, nil
}

// rejected0RTT is called for the client when the server rejects 0-RTT.
func (h *uCryptoSetup) rejected0RTT() {
	h.logger.Debugf("0-RTT was rejected. Dropping 0-RTT keys.")

	h.mutex.Lock()
	had0RTTKeys := h.zeroRTTSealer != nil
	h.zeroRTTSealer = nil
	h.mutex.Unlock()

	if had0RTTKeys {
		h.events = append(h.events, Event{Kind: EventDiscard0RTTKeys})
	}
}

func (h *uCryptoSetup) SetReadKey(el qtls.QUICEncryptionLevel, suiteID uint16, trafficSecret []byte) {
	suite := getCipherSuite(suiteID)
	h.mutex.Lock()
	//nolint:exhaustive // The TLS stack doesn't export Initial keys.
	switch el {
	case qtls.QUICEncryptionLevelEarly:
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
	case qtls.QUICEncryptionLevelHandshake:
		h.handshakeOpener = newLongHeaderOpener(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed Handshake Read keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	case qtls.QUICEncryptionLevelApplication:
		h.aead.SetReadKey(suite, trafficSecret)
		h.has1RTTOpener = true
		if h.logger.Debug() {
			h.logger.Debugf("Installed 1-RTT Read keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	default:
		panic("unexpected read encryption level")
	}
	h.mutex.Unlock()
	h.events = append(h.events, Event{Kind: EventReceivedReadKeys})
	if h.tracer != nil {
		h.tracer.UpdatedKeyFromTLS(qtls.FromTLSEncryptionLevel(el), h.perspective.Opposite())
	}
}

func (h *uCryptoSetup) SetWriteKey(el qtls.QUICEncryptionLevel, suiteID uint16, trafficSecret []byte) {
	suite := getCipherSuite(suiteID)
	h.mutex.Lock()
	//nolint:exhaustive // The TLS stack doesn't export Initial keys.
	switch el {
	case qtls.QUICEncryptionLevelEarly:
		if h.perspective == protocol.PerspectiveServer {
			panic("Received 0-RTT write key for the server")
		}
		h.zeroRTTSealer = newLongHeaderSealer(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		h.mutex.Unlock()
		if h.logger.Debug() {
			h.logger.Debugf("Installed 0-RTT Write keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
		if h.tracer != nil {
			h.tracer.UpdatedKeyFromTLS(protocol.Encryption0RTT, h.perspective)
		}
		// don't set used0RTT here. 0-RTT might still get rejected.
		return
	case qtls.QUICEncryptionLevelHandshake:
		h.handshakeSealer = newLongHeaderSealer(
			createAEAD(suite, trafficSecret, h.version),
			newHeaderProtector(suite, trafficSecret, true, h.version),
		)
		if h.logger.Debug() {
			h.logger.Debugf("Installed Handshake Write keys (using %s)", tls.CipherSuiteName(suite.ID))
		}
	case qtls.QUICEncryptionLevelApplication:
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
			if h.tracer != nil {
				h.tracer.DroppedEncryptionLevel(protocol.Encryption0RTT)
			}
		}
	default:
		panic("unexpected write encryption level")
	}
	h.mutex.Unlock()
	if h.tracer != nil {
		h.tracer.UpdatedKeyFromTLS(qtls.FromTLSEncryptionLevel(el), h.perspective)
	}
}

// WriteRecord is called when TLS writes data
func (h *uCryptoSetup) WriteRecord(encLevel qtls.QUICEncryptionLevel, p []byte) {
	//nolint:exhaustive // handshake records can only be written for Initial and Handshake.
	switch encLevel {
	case qtls.QUICEncryptionLevelInitial:
		h.events = append(h.events, Event{Kind: EventWriteInitialData, Data: p})
	case qtls.QUICEncryptionLevelHandshake:
		h.events = append(h.events, Event{Kind: EventWriteHandshakeData, Data: p})
	case qtls.QUICEncryptionLevelApplication:
		panic("unexpected write")
	default:
		panic(fmt.Sprintf("unexpected write encryption level: %s", encLevel))
	}
}

func (h *uCryptoSetup) DiscardInitialKeys() {
	h.mutex.Lock()
	dropped := h.initialOpener != nil
	h.initialOpener = nil
	h.initialSealer = nil
	h.mutex.Unlock()
	if dropped {
		h.logger.Debugf("Dropping Initial keys.")
	}
}

func (h *uCryptoSetup) handshakeComplete() {
	h.handshakeCompleteTime = time.Now()
	h.events = append(h.events, Event{Kind: EventHandshakeComplete})
}

func (h *uCryptoSetup) SetHandshakeConfirmed() {
	h.aead.SetHandshakeConfirmed()
	// drop Handshake keys
	var dropped bool
	h.mutex.Lock()
	if h.handshakeOpener != nil {
		h.handshakeOpener = nil
		h.handshakeSealer = nil
		dropped = true
	}
	h.mutex.Unlock()
	if dropped {
		h.logger.Debugf("Dropping Handshake keys.")
	}
}

func (h *uCryptoSetup) GetInitialSealer() (LongHeaderSealer, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.initialSealer == nil {
		return nil, ErrKeysDropped
	}
	return h.initialSealer, nil
}

func (h *uCryptoSetup) Get0RTTSealer() (LongHeaderSealer, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.zeroRTTSealer == nil {
		return nil, ErrKeysDropped
	}
	return h.zeroRTTSealer, nil
}

func (h *uCryptoSetup) GetHandshakeSealer() (LongHeaderSealer, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.handshakeSealer == nil {
		if h.initialSealer == nil {
			return nil, ErrKeysDropped
		}
		return nil, ErrKeysNotYetAvailable
	}
	return h.handshakeSealer, nil
}

func (h *uCryptoSetup) Get1RTTSealer() (ShortHeaderSealer, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if !h.has1RTTSealer {
		return nil, ErrKeysNotYetAvailable
	}
	return h.aead, nil
}

func (h *uCryptoSetup) GetInitialOpener() (LongHeaderOpener, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.initialOpener == nil {
		return nil, ErrKeysDropped
	}
	return h.initialOpener, nil
}

func (h *uCryptoSetup) Get0RTTOpener() (LongHeaderOpener, error) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

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
	h.mutex.Lock()
	defer h.mutex.Unlock()

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
	h.mutex.Lock()
	defer h.mutex.Unlock()

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
