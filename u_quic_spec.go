package quic

import (
	"slices"

	tls "github.com/refraction-networking/utls"
)

const (
	DefaultUDPDatagramMinSize = 1200
)

// QUICSpec is the complete description of the QUIC Initial flight a UTransport
// emits: the Initial packet's header and framing (InitialPacketSpec), the TLS
// ClientHello carried in its CRYPTO stream (ClientHelloSpec), and the datagram-level
// and transport-parameter knobs below. It is the QUIC-layer analogue of uTLS's
// ClientHelloSpec — everything a fingerprinter can observe about the flight should be
// reachable from here.
//
// Assign one to UTransport.QUICSpec before dialing:
//
//	ut := &quic.UTransport{Transport: &quic.Transport{Conn: pc}, QUICSpec: spec}
//	conn, err := ut.Dial(ctx, addr, tlsConf, conf)
//
// Fields that randomize per connection (RandomizeTransportParameters, a
// QUICRandomFrames FrameBuilder, ClientTokenPrefix's random tail) are re-drawn on
// every dial, so one spec value can serve many connections. Fields whose value is
// itself random — a GREASE transport parameter's ID, VariableLengthGREASEQTP's
// length — are drawn once when the spec is built, so build a fresh spec per
// connection if those must vary too.
type QUICSpec struct {
	// InitialPacketSpec specifies the QUIC Initial Packet, which includes Initial
	// Packet Headers and Frames.
	InitialPacketSpec InitialPacketSpec

	// ClientHelloSpec specifies the TLS ClientHello to be sent in the first Initial
	// Packet. It is implemented by the uTLS library and a valid ClientHelloSpec
	// for QUIC MUST include (utls).QUICTransportParametersExtension.
	ClientHelloSpec *tls.ClientHelloSpec

	// UDPDatagramMinSize specifies the minimum size of the UDP Datagram (UDP payload).
	// If the UDP Datagram is smaller than this size, zeros will be padded to the end
	// of the UDP Datagram until this size is reached.
	UDPDatagramMinSize int

	// RandomizeTransportParameters, when true, shuffles the QUIC transport parameters
	// (the ClientHelloSpec's QUICTransportParametersExtension list) into a uniformly
	// random permutation per connection, before they are serialized into the Initial
	// CRYPTO stream. This mirrors real Chrome, which randomizes the QTP wire order on
	// every handshake; without it the parameter order is fixed by the spec and becomes
	// a trivial discriminator signal. The shuffle reorders the extension's parameter
	// slice in place at connection-setup time (so a freshly built spec randomizes each
	// connection); it does not change which parameters or values are sent.
	RandomizeTransportParameters bool

	// SuppressTransportParameters lists QUIC transport parameter IDs to drop from the
	// ClientHelloSpec's QUICTransportParametersExtension before it is serialized into
	// the Initial CRYPTO stream. It lets a caller pin the exact on-wire parameter set
	// — most usefully by starting from a parrot (or any shared spec) and removing
	// parameters, instead of restating the whole list.
	//
	// An entry of QTPGrease (27) removes every GREASE-valued parameter (31*N+27), since
	// QUIC fingerprinters bucket all GREASE IDs into that one canonical ID; other
	// entries match the parameter ID exactly. Suppression runs before
	// RandomizeTransportParameters, so the shuffled set is exactly the wire set, and
	// the connection's own view of its parameters is populated from the filtered list.
	//
	// Suppressing a parameter the peer requires (e.g. initial_source_connection_id)
	// produces a ClientHello a conformant server will reject. That is allowed on
	// purpose — mimicry sometimes needs it — but it is the caller's responsibility.
	SuppressTransportParameters []uint64
}

// TransportParameterIDs returns the QUIC transport parameter IDs this spec will put on
// the wire, in the canonical form QUIC fingerprinters use: every GREASE ID (31*N+27) is
// folded to QTPGrease and the result is sorted ascending. SuppressTransportParameters is
// applied, so this is what a dial would actually send. It returns nil if the spec has no
// ClientHelloSpec or no QUICTransportParametersExtension.
//
// Duplicates are deliberately kept, because they are the whole point: a spec listing both
// an explicit tls.FakeQUICTransportParameter{Id: 0x1b} and a GREASE parameter emits two
// distinct IDs on the wire, but a fingerprinter canonicalizes both to 27 and sees it
// twice. That collision is invisible in the spec source and otherwise only surfaces in a
// packet capture. Compare this slice against a target fingerprint's parameter ID list to
// catch it before dialing.
//
// Calling this pins each GREASE parameter's ID, which is drawn randomly on first use, so
// a subsequent dial sends exactly the IDs reported here.
func (s *QUICSpec) TransportParameterIDs() []uint64 {
	if s.ClientHelloSpec == nil {
		return nil
	}
	for _, ext := range s.ClientHelloSpec.Extensions {
		qtp, ok := ext.(*tls.QUICTransportParametersExtension)
		if !ok {
			continue
		}
		SuppressQUICTransportParameters(qtp, s.SuppressTransportParameters)
		ids := make([]uint64, 0, len(qtp.TransportParameters))
		for _, tp := range qtp.TransportParameters {
			id := tp.ID()
			if IsGREASEQTPID(id) {
				id = QTPGrease
			}
			ids = append(ids, id)
		}
		slices.Sort(ids)
		return ids
	}
	return nil
}

// UpdateConfig applies the spec's Config-level overrides to config — currently the
// TokenStore derived from InitialPacketSpec (see InitialPacketSpec.UpdateConfig).
// UTransport.dial calls this after populateConfig and before dialing; a spec field
// that has to reach the connection through Config must be wired in here, or it will
// be silently ignored no matter what the spec sets.
func (s *QUICSpec) UpdateConfig(config *Config) {
	s.InitialPacketSpec.UpdateConfig(config)
}
