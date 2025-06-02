package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/pion/dtls/v3/examples/util"
	quic "github.com/refraction-networking/uquic"
	"github.com/refraction-networking/uquic/internal/kyber"
	tls "github.com/refraction-networking/utls"
)

func main() {
	var remoteAddr = flag.String("raddr", "127.0.0.1:6666", "remote address")
	var localAddr = flag.String("laddr", "127.0.0.1:6667", "remote address")
	var pubkey = flag.String("pubkey", "0b63baad7f2f4bb5b547c53adc0fbb179852910607935e6f4b5639fd989b1156", "pubkey")
	// var covert = flag.String("covert", "1.2.3.4:5678", "covert address")
	flag.Parse()

	laddr, err := net.ResolveUDPAddr("udp", *localAddr)
	util.Check(err)
	addr, err := net.ResolveUDPAddr("udp", *remoteAddr)
	util.Check(err)

	rootCertificate, err := LoadCertificate("certificates/server.pub.pem")
	util.Check(err)
	certPool := x509.NewCertPool()
	cert, err := x509.ParseCertificate(rootCertificate.Certificate[0])
	util.Check(err)
	certPool.AddCert(cert)

	pconn, err := net.ListenUDP("udp", laddr)
	util.Check(err)

	// chSpec, err := tls.UTLSIdToSpec(tls.HelloChrome_131)
	// util.Check(err)

	// quicSpec.ClientHelloSpec = &chSpec

	clientPrivKey := [32]byte{}
	if _, err := rand.Read(clientPrivKey[:]); err != nil {
		panic(err)
	}
	kyberClient := kyber.Client{Host: kyber.NewHost(clientPrivKey)}

	pub, err := hex.DecodeString(*pubkey)
	util.Check(err)

	pub32 := [32]byte{}
	if n := copy(pub32[:], pub); n != 32 {
		panic("key len != 32")
	}

	clientData := []byte("hello world")
	kyberClient.ComputeSharedKey(pub32)
	x25519kyber768Parrot := kyberClient.GenKyber(clientData)

	tp := quic.UTransport{
		Transport: &quic.Transport{
			Conn: pconn,
		},
		QUICSpec: &quic.QUICSpec{
			InitialPacketSpec: quic.InitialPacketSpec{
				SrcConnIDLength:        3,
				DestConnIDLength:       8,
				InitPacketNumberLength: 1,
				InitPacketNumber:       0,
				ClientTokenLength:      0,
				FrameBuilder:           quic.QUICFrames{}, // empty = single crypto
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
							tls.X25519MLKEM768,
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
								Group: tls.X25519MLKEM768,
								Data:  x25519kyber768Parrot,
							},
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
					quic.ShuffleQUICTransportParameters(&tls.QUICTransportParametersExtension{
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
		},
	}

	econn, err := tp.Dial(context.Background(), addr, &tls.Config{
		RootCAs:    certPool,
		NextProtos: []string{"h3"},
	}, &quic.Config{})
	util.Check(err)

	stream, err := econn.OpenStream()
	util.Check(err)

	fmt.Println("Connected; type 'exit' to shutdown gracefully")

	// Simulate a chat session
	util.Chat(stream)

}

// LoadCertificate Load/read certificate(s) from file
func LoadCertificate(path string) (*tls.Certificate, error) {
	rawData, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	var certificate tls.Certificate

	for {
		block, rest := pem.Decode(rawData)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			return nil, errBlockIsNotCertificate
		}

		certificate.Certificate = append(certificate.Certificate, block.Bytes)
		rawData = rest
	}

	if len(certificate.Certificate) == 0 {
		return nil, errNoCertificateFound
	}

	return &certificate, nil
}

var (
	errBlockIsNotCertificate = errors.New("block is not a certificate, unable to load certificates")
	errNoCertificateFound    = errors.New("no certificate found, unable to load certificates")
)
