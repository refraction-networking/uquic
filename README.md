# ![uTLS](docs/utls_logo_small.png) <img src="docs/quic.png" alt="drawing" width="200"/> uQUIC
[![Go Build Status](https://github.com/gaukas/uquic/actions/workflows/go_build.yml/badge.svg?branch=master)](https://github.com/gaukas/uquic/actions/workflows/go_build.yml)
[![Ginkgo Test Status](https://github.com/gaukas/uquic/actions/workflows/ginkgo_test.yml/badge.svg?branch=master)](https://github.com/gaukas/uquic/actions/workflows/ginkgo_test.yml)
[![godoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/refraction-networking/uquic)
---
uQUIC is a fork of [quic-go](https://github.com/refraction-networking/uquic), which provides Initial Packet fingerprinting resistance and other features. While the handshake is still performed by quic-go, this library provides interface to customize the unencrypted Initial Packet which may reveal fingerprint-able information. 

Golang 1.20+ is required.

If you have any questions, bug reports or contributions, you are welcome to publish those on GitHub. You may also reach out to one of the maintainers via gaukas.wang@colorado.edu.

Development is still in progress and we welcome any contributions adding new features or fixing extant bugs.

# Development in Progress
## Development Roadmap
- [ ] Customize Initial Packet 
	- [x] QUIC Header 
	- [ ] QUIC Frame ([#3](https://github.com/gaukas/uquic/issues/3))
		- [x] QUIC Crypto Frame
		- [x] QUIC Padding Frame
		- [x] QUIC Ping Frame
		- [ ] QUIC ACK Frame
	- [x] TLS ClientHello Message (by [uTLS](https://github.com/refraction-networking/utls))
		- [x] QUIC Transport Parameters (in a uTLS extension)
- [ ] Customize Initial ACK behavior ([#1](https://github.com/gaukas/uquic/issues/1), [quic-go#4007](https://github.com/quic-go/quic-go/issues/4007))
- [ ] Customize Initial Retry behavior ([#2](https://github.com/gaukas/uquic/issues/2))
- [ ] Add preset QUIC parrots
	- [ ] Google Chrome parrot
	- [ ] Mozilla Firefox parrot
	- [ ] Apple Safari parrot
	- [ ] Microsoft Edge parrot

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
