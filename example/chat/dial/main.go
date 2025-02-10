package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/pion/dtls/v3/examples/util"
	quic "github.com/refraction-networking/uquic"
	tls "github.com/refraction-networking/utls"
)

func main() {
	var remoteAddr = flag.String("raddr", "127.0.0.1:6666", "remote address")
	var localAddr = flag.String("laddr", "127.0.0.1:6667", "remote address")
	// var pubkey = flag.String("secret", "0b63baad7f2f4bb5b547c53adc0fbb179852910607935e6f4b5639fd989b1156", "shared secret")
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
	quicSpec, err := quic.QUICID2Spec(quic.QUICFirefox_116)
	util.Check(err)

	tp := quic.UTransport{
		Transport: &quic.Transport{
			Conn: pconn,
		},
		QUICSpec: &quicSpec,
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
