# ![uTLS](image/logo_small.png) uQUIC
[![Build Status](https://github.com/refraction-networking/uquic/actions/workflows/go_1_20.yml/badge.svg?branch=master)](https://github.com/refraction-networking/uquic/actions)[![Build Status](https://github.com/refraction-networking/uquic/actions/workflows/go_1_21.yml/badge.svg?branch=master)](https://github.com/refraction-networking/uquic/actions)
[![godoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/refraction-networking/uquic)
---
uQUIC is a fork of "quic-go", which provides Initial Packet fingerprinting resistance and other features. While the handshake is still performed by quic-go, this library provides interface to customize the unencrypted Initial Packet which may reveal fingerprint-able information. 

Golang 1.20+ is required.

If you have any questions, bug reports or contributions, you are welcome to publish those on GitHub. You may also reach out to one of the maintainers via gaukas.wang@colorado.edu.

Development is still in progress and we welcome any contributions adding new features or fixing extant bugs.

# Features
## Initial Packet fingerprinting resistance
uQUIC provides a mechanism to customize the Initial Packet, which is unencrypted and is almost unique to every QUIC client implementation. We provide an interface to customize the Initial Packet and makes the fingerprinting of QUIC clients harder.

### Build a QUIC Spec
A QUIC Spec sets parameters and policies for uQUIC in establishing a QUIC connection. 

```go
func getQUICSpec() *uquic.QUICSpec {
	return &uquic.QUICSpec{
		InitialPacketSpec: uquic.InitialPacketSpec{
			SrcConnIDLength:        3,
			DestConnIDLength:       8,
			InitPacketNumberLength: 1,
			InitPacketNumber:       1,
			ClientTokenLength:      0,
			FrameOrder: uquic.QUICFrames{
				&uquic.QUICFrameCrypto{
					Offset: 0,
					Length: 0,
				},
			},
		},
		ClientHelloSpec: getClientHelloSpec(),
        UDPDatagramMinSize: 1357,
	}
}

func getClientHelloSpec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
        // skipped a few mandatory fields, see uTLS for details
		Extensions: []utls.TLSExtension{
			// skipped a few mandatory extensions, see uTLS for details
			&utls.QUICTransportParametersExtension{
				TransportParameters: utls.TransportParameters{
					utls.InitialMaxStreamDataBidiRemote(0x100000),
					utls.InitialMaxStreamsBidi(16),
					utls.MaxDatagramFrameSize(1200),
					utls.MaxIdleTimeout(30000),
					utls.ActiveConnectionIDLimit(8),
					&utls.GREASEQUICBit{},
					&utls.VersionInformation{
						ChoosenVersion: utls.VERSION_1,
						AvailableVersions: []uint32{
							utls.VERSION_GREASE,
							utls.VERSION_1,
						},
						LegacyID: true,
					},
					utls.InitialMaxStreamsUni(16),
					&utls.GREASE{},
					utls.InitialMaxStreamDataBidiLocal(0xc00000),
					utls.InitialMaxStreamDataUni(0x100000),
					utls.InitialSourceConnectionID([]byte{}),
					utls.MaxAckDelay(20),
					utls.InitialMaxData(0x1800000),
					&utls.DisableActiveMigration{},
				},
			},
		},
	}
}
```