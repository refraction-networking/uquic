package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	tls "github.com/refraction-networking/utls"

	quic "github.com/refraction-networking/uquic"
	"github.com/refraction-networking/uquic/http3"
)

func main() {
	keyLogWriter, err := os.Create("./keylog.txt")
	if err != nil {
		panic(err)
	}

	tlsConf := &tls.Config{
		// ServerName: "quic.tlsfingerprint.io",
		// ServerName: "www.cloudflare.com",
		// MinVersion:   tls.VersionTLS13,
		KeyLogWriter: keyLogWriter,
		// NextProtos:   []string{"h3"},
	}

	quicConf := &quic.Config{}

	quicSpec, err := quic.QUICID2Spec(quic.QUICFirefox_116)
	// quicSpec, err := quic.QUICID2Spec(quic.QUICChrome_115)
	if err != nil {
		log.Fatal(err)
	}

	transport := &http3.Transport{
		TLSClientConfig: tlsConf,
		QUICConfig:      quicConf,
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			udpConn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}

			network := "udp"
			ut := &quic.UTransport{
				Transport: &quic.Transport{
					Conn: udpConn,
				},
				QUICSpec: &quicSpec,
			}

			udpAddr, err := net.ResolveUDPAddr(network, addr)
			if err != nil {
				return nil, err
			}

			conn, err := ut.DialEarly(ctx, udpAddr, tlsCfg, cfg)

			return conn, err

		},
	}

	defer transport.Close()

	hclient := &http.Client{
		Transport: transport,
	}

	// addr := "https://quic.tlsfingerprint.io/qfp/?beautify=true"
	addr := "https://www.cloudflare.com"

	rsp, err := hclient.Get(addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Got response for %s: %#v", addr, rsp)

	body := &bytes.Buffer{}
	_, err = io.Copy(body, rsp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Response Body: %s", body.Bytes())
}
