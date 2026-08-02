package quic

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	mrand "math/rand"

	tls "github.com/refraction-networking/utls"
)

// QUICID names one built-in client fingerprint that QUICID2Spec can expand into a
// ready-made QUICSpec — the QUIC-layer analogue of uTLS's ClientHelloID. The package
// vars below (QUICChrome_146, QUICFirefox_116, …) are the available IDs; a client with
// several observed variants gets one ID per variant, with the unsuffixed name aliasing
// the most common one.
type QUICID struct {
	Client string

	// Version specifies version of a mimicked clients (e.g. browsers).
	Version string

	// Fingerprint is a unique identifier for each different QUIC client/spec.
	Fingerprint string
}

const (
	// clients
	quicFirefox = "Firefox"
	quicChrome  = "Chrome"
	quicIOS     = "iOS"
	quicAndroid = "Android"
	quicEdge    = "Edge"
	quicSafari  = "Safari"
)

var (
	QUICFirefox_116  = QUICFirefox_116A                               // point to most-popular 8-byte DCID
	QUICFirefox_116A = QUICID{quicFirefox, "116", "31ea0e4ffd75b477"} // DCID.len = 8
	QUICFirefox_116B = QUICID{quicFirefox, "116", "d07d3c9152fbc5e0"} // DCID.len = 9
	QUICFirefox_116C = QUICID{quicFirefox, "116", "c74f87b2a9ccc006"} // DCID.len = 15
	// TODO: add Firefox fingerprints with Token and PSK extension

	QUICChrome_115      = QUICChrome_115_IPv4                               // IPv4 is still more popular
	QUICChrome_115_IPv4 = QUICID{quicChrome, "115", "beeb454235791d5c"}     // IPv4: UDP payload 20-byte longer than IPv6 due to padding
	QUICChrome_115_IPv6 = QUICID{quicChrome, "115_ip6", "beeb454235791d5c"} // IPv6
	// TODO: add Chrome fingerprints with Token and PSK extension

	QUICChrome_146      = QUICChrome_146_IPv4                               // IPv4 is still more popular
	QUICChrome_146_IPv4 = QUICID{quicChrome, "146", "a3c5e1f2b7d9048a"}     // IPv4: 2-datagram Initial (X25519MLKEM768 key share)
	QUICChrome_146_IPv6 = QUICID{quicChrome, "146_ip6", "c2d8f3a1e6b05794"} // IPv6

	// TODO: add more QUIC clients and versions
)

// QUICID2Spec returns the QUICSpec that mimics the client named by id, or an error for
// an unknown ID. Each call builds a fresh spec, so per-spec random draws (GREASE
// parameter IDs and lengths, ChromeRandomInitialRTT) are re-drawn — call it per
// connection rather than caching one result if those values must vary.
//
// The returned spec is a starting point, not a frozen artifact: mutate its fields, or
// set QUICSpec.SuppressTransportParameters, to derive a variant without restating the
// whole parameter list.
func QUICID2Spec(id QUICID) (QUICSpec, error) {
	switch id {
	case QUICChrome_115_IPv4:
		return QUICSpec{
			InitialPacketSpec: InitialPacketSpec{
				SrcConnIDLength:        0,
				DestConnIDLength:       8,
				InitPacketNumberLength: 1,
				InitPacketNumber:       1, // Chrome is special that it starts with 1 not 0
				ClientTokenLength:      0,
				FrameBuilder: &QUICRandomFrames{ // Chrome randomly inserts padding frames
					MinPING:    0,
					MaxPING:    10,
					MinCRYPTO:  1,
					MaxCRYPTO:  10,
					MinPADDING: 3,
					MaxPADDING: 6,
					Length:     1231 - 16, // 16-byte for Auth Tag
				},
			},
			ClientHelloSpec: &tls.ClientHelloSpec{
				TLSVersMin: tls.VersionTLS13,
				TLSVersMax: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
				},
				CompressionMethods: []uint8{
					0x0, // no compression
				},
				Extensions: tls.ShuffleChromeTLSExtensions([]tls.TLSExtension{
					ShuffleQUICTransportParameters(&tls.QUICTransportParametersExtension{ // Order of QTPs are always shuffled
						TransportParameters: tls.TransportParameters{
							tls.InitialMaxStreamsUni(103),
							tls.MaxIdleTimeout(30000),
							tls.InitialMaxData(15728640),
							tls.InitialMaxStreamDataUni(6291456),
							&tls.VersionInformation{
								ChoosenVersion: tls.VERSION_1,
								AvailableVersions: []uint32{
									tls.VERSION_GREASE,
									tls.VERSION_1,
								},
								LegacyID: true,
							},
							&tls.FakeQUICTransportParameter{ // google_quic_version
								Id:  0x4752,
								Val: []byte{00, 00, 00, 01}, // Google QUIC version 1
							},
							&tls.FakeQUICTransportParameter{ // google_connection_options
								Id:  0x3128,
								Val: []byte{0x52, 0x56, 0x43, 0x4d},
							},
							tls.MaxDatagramFrameSize(65536),
							tls.InitialMaxStreamsBidi(100),
							tls.InitialMaxStreamDataBidiLocal(6291456),
							VariableLengthGREASEQTP(0x10), // Random length for GREASE QTP
							tls.InitialSourceConnectionID([]byte{}),
							tls.MaxUDPPayloadSize(1472),
							tls.InitialMaxStreamDataBidiRemote(6291456),
						},
					}),
					&tls.ApplicationSettingsExtension{
						SupportedProtocols: []string{
							"h3",
						},
					},
					&tls.UtlsCompressCertExtension{
						Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionBrotli,
						},
					},
					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{
							{
								Group: tls.X25519,
							},
						},
					},
					&tls.SignatureAlgorithmsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.PSSWithSHA256,
							tls.PKCS1WithSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.PSSWithSHA384,
							tls.PKCS1WithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA512,
							tls.PKCS1WithSHA1,
						},
					},
					&tls.SNIExtension{},
					&tls.SupportedCurvesExtension{
						Curves: []tls.CurveID{
							tls.CurveX25519,
							tls.CurveSECP256R1,
							tls.CurveSECP384R1,
						},
					},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{
							tls.PskModeDHE,
						},
					},
					&tls.ALPNExtension{
						AlpnProtocols: []string{
							"h3",
						},
					},
					&tls.SupportedVersionsExtension{
						Versions: []uint16{
							tls.VersionTLS13,
						},
					},
				}),
			},
		}, nil
	case QUICChrome_115_IPv6:
		return QUICSpec{
			InitialPacketSpec: InitialPacketSpec{
				SrcConnIDLength:        0,
				DestConnIDLength:       8,
				InitPacketNumberLength: 1,
				InitPacketNumber:       1, // Chrome is special that it starts with 1 not 0
				ClientTokenLength:      0,
				FrameBuilder: &QUICRandomFrames{ // Chrome randomly inserts padding frames
					MinPING:    0,
					MaxPING:    10,
					MinCRYPTO:  1,
					MaxCRYPTO:  10,
					MinPADDING: 3,
					MaxPADDING: 6,
					Length:     1211 - 16, // IPv6 pads to a length that is 20-byte shorter than IPv4's version
				},
			},
			ClientHelloSpec: &tls.ClientHelloSpec{
				TLSVersMin: tls.VersionTLS13,
				TLSVersMax: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
				},
				CompressionMethods: []uint8{
					0x0,
				},
				Extensions: tls.ShuffleChromeTLSExtensions([]tls.TLSExtension{
					ShuffleQUICTransportParameters(&tls.QUICTransportParametersExtension{ // Order of QTPs are always shuffled
						TransportParameters: tls.TransportParameters{
							tls.InitialMaxStreamsUni(103),
							tls.MaxIdleTimeout(30000),
							tls.InitialMaxData(15728640),
							tls.InitialMaxStreamDataUni(6291456),
							&tls.VersionInformation{
								ChoosenVersion: tls.VERSION_1,
								AvailableVersions: []uint32{
									tls.VERSION_GREASE,
									tls.VERSION_1,
								},
								LegacyID: true,
							},
							&tls.FakeQUICTransportParameter{ // google_quic_version
								Id:  0x4752,
								Val: []byte{00, 00, 00, 01}, // Google QUIC version 1
							},
							&tls.FakeQUICTransportParameter{ // google_connection_options
								Id:  0x3128,
								Val: []byte{0x52, 0x56, 0x43, 0x4d},
							},
							tls.MaxDatagramFrameSize(65536),
							tls.InitialMaxStreamsBidi(100),
							tls.InitialMaxStreamDataBidiLocal(6291456),
							VariableLengthGREASEQTP(0x10), // Random length for GREASE QTP
							tls.InitialSourceConnectionID([]byte{}),
							tls.MaxUDPPayloadSize(1472),
							tls.InitialMaxStreamDataBidiRemote(6291456),
						},
					}),
					&tls.ApplicationSettingsExtension{
						SupportedProtocols: []string{
							"h3",
						},
					},
					&tls.UtlsCompressCertExtension{
						Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionBrotli,
						},
					},
					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{
							{
								Group: tls.X25519,
							},
						},
					},
					&tls.SignatureAlgorithmsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.PSSWithSHA256,
							tls.PKCS1WithSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.PSSWithSHA384,
							tls.PKCS1WithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA512,
							tls.PKCS1WithSHA1,
						},
					},
					&tls.SNIExtension{},
					&tls.SupportedCurvesExtension{
						Curves: []tls.CurveID{
							tls.CurveX25519,
							tls.CurveSECP256R1,
							tls.CurveSECP384R1,
						},
					},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{
							tls.PskModeDHE,
						},
					},
					&tls.ALPNExtension{
						AlpnProtocols: []string{
							"h3",
						},
					},
					&tls.SupportedVersionsExtension{
						Versions: []uint16{
							tls.VersionTLS13,
						},
					},
				}),
			},
		}, nil
	case QUICFirefox_116A:
		return QUICSpec{
			InitialPacketSpec: InitialPacketSpec{
				SrcConnIDLength:        3,
				DestConnIDLength:       8,
				InitPacketNumberLength: 1,
				InitPacketNumber:       0,
				ClientTokenLength:      0,
				FrameBuilder:           QUICFrames{}, // empty = single crypto
			},
			ClientHelloSpec: &tls.ClientHelloSpec{
				TLSVersMin: tls.VersionTLS13,
				TLSVersMax: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
				},
				CompressionMethods: []uint8{
					0x0,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{
						Curves: []tls.CurveID{
							tls.CurveX25519,
							tls.CurveSECP256R1,
							tls.CurveSECP384R1,
							tls.CurveSECP521R1,
							tls.FakeCurveFFDHE2048,
							tls.FakeCurveFFDHE3072,
							tls.FakeCurveFFDHE4096,
							tls.FakeCurveFFDHE6144,
							tls.FakeCurveFFDHE8192,
						},
					},
					&tls.ALPNExtension{
						AlpnProtocols: []string{
							"h3",
						},
					},
					&tls.StatusRequestExtension{},
					&tls.FakeDelegatedCredentialsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
						},
					},
					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{
							{
								Group: tls.X25519,
							},
						},
					},
					&tls.SupportedVersionsExtension{
						Versions: []uint16{
							tls.VersionTLS13,
						},
					},
					&tls.SignatureAlgorithmsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
							tls.PSSWithSHA256,
							tls.PSSWithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA256,
							tls.PKCS1WithSHA384,
							tls.PKCS1WithSHA512,
							tls.PKCS1WithSHA1,
						},
					},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{
							tls.PskModeDHE,
						},
					},
					&tls.FakeRecordSizeLimitExtension{
						Limit: 0x4001,
					},
					ShuffleQUICTransportParameters(&tls.QUICTransportParametersExtension{
						TransportParameters: tls.TransportParameters{
							tls.InitialMaxStreamDataBidiRemote(0x100000),
							tls.InitialMaxStreamsBidi(16),
							tls.MaxDatagramFrameSize(1200),
							tls.MaxIdleTimeout(30000),
							tls.ActiveConnectionIDLimit(8),
							&tls.GREASEQUICBit{},
							&tls.VersionInformation{
								ChoosenVersion: tls.VERSION_1,
								AvailableVersions: []uint32{
									tls.VERSION_GREASE,
									tls.VERSION_1,
								},
								LegacyID: true,
							},
							tls.InitialMaxStreamsUni(16),
							&tls.GREASETransportParameter{
								Length: 2, // Firefox uses 2-byte GREASE values
							},
							tls.InitialMaxStreamDataBidiLocal(0xc00000),
							tls.InitialMaxStreamDataUni(0x100000),
							tls.InitialSourceConnectionID([]byte{}),
							tls.MaxAckDelay(20),
							tls.InitialMaxData(0x1800000),
							&tls.DisableActiveMigration{},
						},
					}),
					&tls.UtlsPaddingExtension{
						GetPaddingLen: tls.BoringPaddingStyle,
					},
				},
			},
			UDPDatagramMinSize: 1357, // Firefox pads with zeroes at the end of UDP datagrams
		}, nil
	case QUICFirefox_116B:
		return QUICSpec{
			InitialPacketSpec: InitialPacketSpec{
				SrcConnIDLength:        3,
				DestConnIDLength:       9,
				InitPacketNumberLength: 1,
				InitPacketNumber:       0,
				ClientTokenLength:      0,
				FrameBuilder:           QUICFrames{},
			},
			ClientHelloSpec: &tls.ClientHelloSpec{
				TLSVersMin: tls.VersionTLS13,
				TLSVersMax: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
				},
				CompressionMethods: []uint8{
					0x0,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{
						Curves: []tls.CurveID{
							tls.CurveX25519,
							tls.CurveSECP256R1,
							tls.CurveSECP384R1,
							tls.CurveSECP521R1,
							tls.FakeCurveFFDHE2048,
							tls.FakeCurveFFDHE3072,
							tls.FakeCurveFFDHE4096,
							tls.FakeCurveFFDHE6144,
							tls.FakeCurveFFDHE8192,
						},
					},
					&tls.ALPNExtension{
						AlpnProtocols: []string{
							"h3",
						},
					},
					&tls.StatusRequestExtension{},
					&tls.FakeDelegatedCredentialsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
						},
					},
					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{
							{
								Group: tls.X25519,
							},
						},
					},
					&tls.SupportedVersionsExtension{
						Versions: []uint16{
							tls.VersionTLS13,
						},
					},
					&tls.SignatureAlgorithmsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
							tls.PSSWithSHA256,
							tls.PSSWithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA256,
							tls.PKCS1WithSHA384,
							tls.PKCS1WithSHA512,
							tls.PKCS1WithSHA1,
						},
					},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{
							tls.PskModeDHE,
						},
					},
					&tls.FakeRecordSizeLimitExtension{
						Limit: 0x4001,
					},
					ShuffleQUICTransportParameters(&tls.QUICTransportParametersExtension{
						TransportParameters: tls.TransportParameters{
							tls.InitialMaxStreamDataBidiRemote(0x100000),
							tls.InitialMaxStreamsBidi(16),
							tls.MaxDatagramFrameSize(1200),
							tls.MaxIdleTimeout(30000),
							tls.ActiveConnectionIDLimit(8),
							&tls.GREASEQUICBit{},
							&tls.VersionInformation{
								ChoosenVersion: tls.VERSION_1,
								AvailableVersions: []uint32{
									tls.VERSION_GREASE,
									tls.VERSION_1,
								},
								LegacyID: true,
							},
							tls.InitialMaxStreamsUni(16),
							&tls.GREASETransportParameter{
								Length: 2, // Firefox uses 2-byte GREASE values
							},
							tls.InitialMaxStreamDataBidiLocal(0xc00000),
							tls.InitialMaxStreamDataUni(0x100000),
							tls.InitialSourceConnectionID([]byte{}),
							tls.MaxAckDelay(20),
							tls.InitialMaxData(0x1800000),
							&tls.DisableActiveMigration{},
						},
					}),
					&tls.UtlsPaddingExtension{
						GetPaddingLen: tls.BoringPaddingStyle,
					},
				},
			},
			UDPDatagramMinSize: 1357,
		}, nil
	case QUICFirefox_116C:
		return QUICSpec{
			InitialPacketSpec: InitialPacketSpec{
				SrcConnIDLength:        3,
				DestConnIDLength:       15,
				InitPacketNumberLength: 1,
				InitPacketNumber:       0,
				ClientTokenLength:      0,
				FrameBuilder:           QUICFrames{},
			},
			ClientHelloSpec: &tls.ClientHelloSpec{
				TLSVersMin: tls.VersionTLS13,
				TLSVersMax: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_CHACHA20_POLY1305_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
				},
				CompressionMethods: []uint8{
					0x0,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{
						Renegotiation: tls.RenegotiateOnceAsClient,
					},
					&tls.SupportedCurvesExtension{
						Curves: []tls.CurveID{
							tls.CurveX25519,
							tls.CurveSECP256R1,
							tls.CurveSECP384R1,
							tls.CurveSECP521R1,
							tls.FakeCurveFFDHE2048,
							tls.FakeCurveFFDHE3072,
							tls.FakeCurveFFDHE4096,
							tls.FakeCurveFFDHE6144,
							tls.FakeCurveFFDHE8192,
						},
					},
					&tls.ALPNExtension{
						AlpnProtocols: []string{
							"h3",
						},
					},
					&tls.StatusRequestExtension{},
					&tls.FakeDelegatedCredentialsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
						},
					},
					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{
							{
								Group: tls.X25519,
							},
						},
					},
					&tls.SupportedVersionsExtension{
						Versions: []uint16{
							tls.VersionTLS13,
						},
					},
					&tls.SignatureAlgorithmsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.ECDSAWithP521AndSHA512,
							tls.ECDSAWithSHA1,
							tls.PSSWithSHA256,
							tls.PSSWithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA256,
							tls.PKCS1WithSHA384,
							tls.PKCS1WithSHA512,
							tls.PKCS1WithSHA1,
						},
					},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{
							tls.PskModeDHE,
						},
					},
					&tls.FakeRecordSizeLimitExtension{
						Limit: 0x4001,
					},
					ShuffleQUICTransportParameters(&tls.QUICTransportParametersExtension{
						TransportParameters: tls.TransportParameters{
							tls.InitialMaxStreamDataBidiRemote(0x100000),
							tls.InitialMaxStreamsBidi(16),
							tls.MaxDatagramFrameSize(1200),
							tls.MaxIdleTimeout(30000),
							tls.ActiveConnectionIDLimit(8),
							&tls.GREASEQUICBit{},
							&tls.VersionInformation{
								ChoosenVersion: tls.VERSION_1,
								AvailableVersions: []uint32{
									tls.VERSION_GREASE,
									tls.VERSION_1,
								},
								LegacyID: true,
							},
							tls.InitialMaxStreamsUni(16),
							&tls.GREASETransportParameter{
								Length: 2,
							},
							tls.InitialMaxStreamDataBidiLocal(0xc00000),
							tls.InitialMaxStreamDataUni(0x100000),
							tls.InitialSourceConnectionID([]byte{}),
							tls.MaxAckDelay(20),
							tls.InitialMaxData(0x1800000),
							&tls.DisableActiveMigration{},
						},
					}),
					&tls.UtlsPaddingExtension{
						GetPaddingLen: tls.BoringPaddingStyle,
					},
				},
			},
			UDPDatagramMinSize: 1357,
		}, nil
	case QUICChrome_146_IPv4:
		// Chrome 146 sends 2 Initial datagrams because the ClientHello (~1734 bytes with
		// X25519MLKEM768's 1216-byte key share) exceeds a single QUIC Initial payload.
		// quic-go automatically splits the CRYPTO stream; QUICRandomFrames.Length controls
		// per-datagram payload size. Per-packet PN encoding: 1 byte for PN=1, 2 bytes for PN=2.
		return QUICSpec{
			InitialPacketSpec: InitialPacketSpec{
				SrcConnIDLength:  0,
				DestConnIDLength: 8,
				// Per-packet PN encoding lengths observed in the Chrome 146 reference pcap:
				//   Packet 1 (PN=1): 1-byte encoding
				//   Packet 2 (PN=2): 2-byte encoding
				// InitPacketNumberLength is intentionally left 0; InitPacketNumberLengths takes precedence.
				InitPacketNumber:        1, // Chrome starts at 1
				InitPacketNumberLengths: []PacketNumberLen{1, 2},
				ClientTokenLength:       0,
				FrameBuilder: &QUICRandomFrames{
					// Informed by single pcap sample:
					//   Packet 1: 3 PINGs, ~11 CRYPTOs, 4 PADDINGs
					//   Packet 2: 2 PINGs, 6 CRYPTOs, 3 PADDINGs
					// Chrome heavily fragments CRYPTO across multiple frames; randomize within range.
					MinPING:    1,
					MaxPING:    4,
					MinCRYPTO:  6,
					MaxCRYPTO:  14,
					MinPADDING: 2,
					MaxPADDING: 6,
					Length:     1231 - 16, // QUIC payload target: 1231 bytes; 16-byte AEAD auth tag
				},
			},
			ClientHelloSpec: &tls.ClientHelloSpec{
				TLSVersMin: tls.VersionTLS13,
				TLSVersMax: tls.VersionTLS13,
				CipherSuites: []uint16{
					// QUIC-only: TLS 1.3 suites only, no GREASE, no TLS 1.2 suites
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
				},
				CompressionMethods: []uint8{
					0x0, // no compression
				},
				Extensions: tls.ShuffleChromeTLSExtensions([]tls.TLSExtension{
					ShuffleQUICTransportParameters(&tls.QUICTransportParametersExtension{
						TransportParameters: tls.TransportParameters{
							// Observed QTP order (shuffled per connection):
							// 0x06 initial_max_stream_data_bidi_remote
							// 0x20 max_datagram_frame_size
							// 0x11 version_information
							// 0x03 max_udp_payload_size
							// 0x01 max_idle_timeout
							// 0x3127 google_initial_rtt (new in Chrome 146)
							// 0x04 initial_max_data
							// 0x07 initial_max_stream_data_uni
							// 0x0f initial_source_connection_id
							// GREASE
							// 0x3128 google_connection_options ("10AF", changed from "RVCM" in Chrome 115)
							// 0x05 initial_max_stream_data_bidi_local
							// 0x08 initial_max_streams_bidi
							// 0x09 initial_max_streams_uni
							// Note: 0x4752 (google_quic_version) was removed vs Chrome 115
							tls.InitialMaxStreamDataBidiRemote(6291456),
							tls.MaxDatagramFrameSize(65536),
							&tls.VersionInformation{
								ChoosenVersion: tls.VERSION_1,
								AvailableVersions: []uint32{
									tls.VERSION_GREASE,
									tls.VERSION_1,
								},
								LegacyID: true,
							},
							tls.MaxUDPPayloadSize(1472),
							tls.MaxIdleTimeout(30000),
							ChromeRandomInitialRTT(), // 0x3127: random 1000–20000 µs per connection
							tls.InitialMaxData(15728640),
							tls.InitialMaxStreamDataUni(6291456),
							tls.InitialSourceConnectionID([]byte{}),
							VariableLengthGREASEQTP(0x10),
							&tls.FakeQUICTransportParameter{ // 0x3128 google_connection_options
								Id:  0x3128,
								Val: []byte{0x31, 0x30, 0x41, 0x46}, // "10AF" (was "RVCM" in Chrome 115)
							},
							tls.InitialMaxStreamDataBidiLocal(6291456),
							tls.InitialMaxStreamsBidi(100),
							tls.InitialMaxStreamsUni(103),
						},
					}),
					&tls.ALPNExtension{
						AlpnProtocols: []string{"h3"},
					},
					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{
							{Group: tls.X25519MLKEM768}, // post-quantum hybrid (causes 2-datagram Initial)
							{Group: tls.X25519},
						},
					},
					&tls.SupportedCurvesExtension{
						Curves: []tls.CurveID{
							tls.X25519MLKEM768,
							tls.CurveX25519,
							tls.CurveSECP256R1,
							tls.CurveSECP384R1,
						},
					},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{tls.PskModeDHE},
					},
					&tls.SignatureAlgorithmsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.PSSWithSHA256,
							tls.PKCS1WithSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.PSSWithSHA384,
							tls.PKCS1WithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA512,
							tls.PKCS1WithSHA1,
						},
					},
					&tls.UtlsCompressCertExtension{
						Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli},
					},
					tls.BoringGREASEECH(), // GREASE ECH outer (new in Chrome 133+)
					&tls.ApplicationSettingsExtensionNew{ // 0x44cd (new codepoint, Chrome 133+)
						SupportedProtocols: []string{"h3"},
					},
					&tls.SupportedVersionsExtension{
						Versions: []uint16{tls.VersionTLS13},
					},
					&tls.SNIExtension{},
				}),
			},
			// No UDPDatagramMinSize: QUICRandomFrames.Length already pads each datagram to ~1232 bytes.
		}, nil
	case QUICChrome_146_IPv6:
		// IPv6 variant: identical to IPv4 except the datagram payload target is 20 bytes shorter,
		// matching Chrome's observed behavior (IPv6 header is 20 bytes larger than IPv4).
		return QUICSpec{
			InitialPacketSpec: InitialPacketSpec{
				SrcConnIDLength:         0,
				DestConnIDLength:        8,
				InitPacketNumber:        1,
				InitPacketNumberLengths: []PacketNumberLen{1, 2},
				ClientTokenLength:       0,
				FrameBuilder: &QUICRandomFrames{
					MinPING:    1,
					MaxPING:    4,
					MinCRYPTO:  6,
					MaxCRYPTO:  14,
					MinPADDING: 2,
					MaxPADDING: 6,
					Length:     1211 - 16, // 20 bytes shorter than IPv4 (IPv6 header overhead)
				},
			},
			ClientHelloSpec: &tls.ClientHelloSpec{
				TLSVersMin: tls.VersionTLS13,
				TLSVersMax: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
				},
				CompressionMethods: []uint8{0x0},
				Extensions: tls.ShuffleChromeTLSExtensions([]tls.TLSExtension{
					ShuffleQUICTransportParameters(&tls.QUICTransportParametersExtension{
						TransportParameters: tls.TransportParameters{
							tls.InitialMaxStreamDataBidiRemote(6291456),
							tls.MaxDatagramFrameSize(65536),
							&tls.VersionInformation{
								ChoosenVersion: tls.VERSION_1,
								AvailableVersions: []uint32{
									tls.VERSION_GREASE,
									tls.VERSION_1,
								},
								LegacyID: true,
							},
							tls.MaxUDPPayloadSize(1472),
							tls.MaxIdleTimeout(30000),
							ChromeRandomInitialRTT(),
							tls.InitialMaxData(15728640),
							tls.InitialMaxStreamDataUni(6291456),
							tls.InitialSourceConnectionID([]byte{}),
							VariableLengthGREASEQTP(0x10),
							&tls.FakeQUICTransportParameter{
								Id:  0x3128,
								Val: []byte{0x31, 0x30, 0x41, 0x46}, // "10AF"
							},
							tls.InitialMaxStreamDataBidiLocal(6291456),
							tls.InitialMaxStreamsBidi(100),
							tls.InitialMaxStreamsUni(103),
						},
					}),
					&tls.ALPNExtension{
						AlpnProtocols: []string{"h3"},
					},
					&tls.KeyShareExtension{
						KeyShares: []tls.KeyShare{
							{Group: tls.X25519MLKEM768},
							{Group: tls.X25519},
						},
					},
					&tls.SupportedCurvesExtension{
						Curves: []tls.CurveID{
							tls.X25519MLKEM768,
							tls.CurveX25519,
							tls.CurveSECP256R1,
							tls.CurveSECP384R1,
						},
					},
					&tls.PSKKeyExchangeModesExtension{
						Modes: []uint8{tls.PskModeDHE},
					},
					&tls.SignatureAlgorithmsExtension{
						SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.PSSWithSHA256,
							tls.PKCS1WithSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.PSSWithSHA384,
							tls.PKCS1WithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA512,
							tls.PKCS1WithSHA1,
						},
					},
					&tls.UtlsCompressCertExtension{
						Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionBrotli},
					},
					tls.BoringGREASEECH(),
					&tls.ApplicationSettingsExtensionNew{
						SupportedProtocols: []string{"h3"},
					},
					&tls.SupportedVersionsExtension{
						Versions: []uint16{tls.VersionTLS13},
					},
					&tls.SNIExtension{},
				}),
			},
		}, nil
	default:
		return QUICSpec{}, fmt.Errorf("unknown QUIC ID: %v", id)
	}
}

// ChromeRandomInitialRTT returns a FakeQUICTransportParameter for google_initial_rtt (0x3127).
// Chrome 146 includes this parameter with a random realistic RTT value in microseconds.
// The observed value in the reference pcap was 7740 µs; the range 1000–20000 µs covers
// typical network conditions. Value is encoded as a 2-byte QUIC varint (high bits = 0b01).
func ChromeRandomInitialRTT() *tls.FakeQUICTransportParameter {
	const minRTT, maxRTT = 1000, 20000
	r, err := rand.Int(rand.Reader, big.NewInt(maxRTT-minRTT))
	if err != nil {
		panic(err)
	}
	rtt := uint16(minRTT + r.Int64())
	// 2-byte QUIC varint: top 2 bits = 01, remaining 14 bits = value
	val := []byte{byte(0x40 | byte(rtt>>8)), byte(rtt)}
	return &tls.FakeQUICTransportParameter{Id: 0x3127, Val: val}
}

// ShuffleTLSExtensions permutes exts uniformly at random, in place, and returns it.
// Every extension moves, including ones real clients keep pinned — GREASE, padding and
// pre_shared_key (which RFC 8446 requires last). For a Chrome-shaped ClientHello use
// utls.ShuffleChromeTLSExtensions instead, which holds those positions fixed.
func ShuffleTLSExtensions(exts []tls.TLSExtension) []tls.TLSExtension {
	mrand.Shuffle(len(exts), func(i, j int) {
		exts[i], exts[j] = exts[j], exts[i]
	})
	return exts
}

// ShuffleQUICTransportParameters permutes qtp's transport parameters uniformly at
// random, in place, returning qtp for chaining. Real Chrome randomizes the QTP wire
// order on every handshake, so a fixed order is a trivial discriminator signal.
//
// Prefer QUICSpec.RandomizeTransportParameters over calling this directly: the spec
// field runs the same shuffle at connection setup, which re-randomizes every dial even
// when one spec value is reused, and it runs after SuppressTransportParameters so the
// shuffled set is exactly the wire set. Calling this from spec-construction code only
// randomizes as often as the spec is rebuilt.
//
// Like SuppressQUICTransportParameters, this mutates qtp.TransportParameters and must
// run before uTLS marshals the extension, which caches its bytes on the first Len().
func ShuffleQUICTransportParameters(qtp *tls.QUICTransportParametersExtension) *tls.QUICTransportParametersExtension {
	// shuffle the order of parameters
	mrand.Shuffle(len(qtp.TransportParameters), func(i, j int) {
		qtp.TransportParameters[i], qtp.TransportParameters[j] = qtp.TransportParameters[j], qtp.TransportParameters[i]
	})
	return qtp
}

// QTPGrease is the canonical ID QUIC fingerprinters use for every GREASE transport
// parameter (the reserved IDs are 31*N+27, of which 27 is the smallest). Pass it in
// QUICSpec.SuppressTransportParameters to drop GREASE parameters whatever ID they drew.
const QTPGrease uint64 = 27

// IsGREASEQTPID reports whether id is one of the reserved GREASE transport parameter
// IDs, i.e. 31*N+27 for some N >= 0. See RFC 9000 §18.1.
func IsGREASEQTPID(id uint64) bool {
	return id >= QTPGrease && (id-QTPGrease)%31 == 0
}

// SuppressQUICTransportParameters removes from qtp every transport parameter whose ID
// is listed in suppress, returning qtp for chaining. A suppress entry of QTPGrease
// matches every GREASE ID, not just 27 — fingerprinters canonicalize them all to 27, so
// suppressing "27" has to mean "the GREASE parameter" to be useful.
//
// This mutates qtp.TransportParameters in place and must therefore run before uTLS
// marshals the extension (it caches the result on the first Len() call). It is
// idempotent, so re-applying it to a reused spec is harmless.
func SuppressQUICTransportParameters(qtp *tls.QUICTransportParametersExtension, suppress []uint64) *tls.QUICTransportParametersExtension {
	if qtp == nil || len(suppress) == 0 {
		return qtp
	}

	var suppressGREASE bool
	ids := make(map[uint64]struct{}, len(suppress))
	for _, id := range suppress {
		if id == QTPGrease {
			suppressGREASE = true
			continue
		}
		ids[id] = struct{}{}
	}

	kept := qtp.TransportParameters[:0]
	for _, tp := range qtp.TransportParameters {
		// ID() is not pure for GREASE parameters: the first call draws and memoizes the
		// random ID, so call it once and reuse the value.
		id := tp.ID()
		if _, drop := ids[id]; drop {
			continue
		}
		if suppressGREASE && IsGREASEQTPID(id) {
			continue
		}
		kept = append(kept, tp)
	}
	qtp.TransportParameters = kept
	return qtp
}

// VariableLengthGREASEQTP returns a GREASE transport parameter carrying a random number
// of random bytes, uniform over [0, maxLen). Chrome's GREASE parameter varies in length
// between handshakes, so a fixed length is itself a fingerprint.
func VariableLengthGREASEQTP(maxLen int) *tls.GREASETransportParameter {
	if maxLen <= 1 {
		return &tls.GREASETransportParameter{}
	}
	if maxLen > math.MaxUint16 {
		maxLen = math.MaxUint16
	}

	// get random length for GREASE
	greaseLen, err := rand.Int(rand.Reader, big.NewInt(int64(maxLen)))
	if err != nil {
		panic(err)
	}

	return &tls.GREASETransportParameter{
		Length: uint16(greaseLen.Uint64()),
	}
}
