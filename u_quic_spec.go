package quic

import tls "github.com/refraction-networking/utls"

const (
	DefaultUDPDatagramMinSize = 1200
)

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
}

func (s *QUICSpec) UpdateConfig(config *Config) {
	s.InitialPacketSpec.UpdateConfig(config)
}
