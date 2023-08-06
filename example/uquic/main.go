package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
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

	roundTripper := &http3.RoundTripper{
		TLSClientConfig: tlsConf,
		QuicConfig:      quicConf,
	}

	quicSpec, err := quic.QUICID2Spec(quic.QUICFirefox_116)
	// quicSpec, err := quic.QUICID2Spec(quic.QUICChrome_115)
	if err != nil {
		log.Fatal(err)
	}

	uRoundTripper := http3.GetURoundTripper(
		roundTripper,
		&quicSpec,
		// getCRQUICSpec(),
		nil,
	)
	defer uRoundTripper.Close()

	hclient := &http.Client{
		Transport: uRoundTripper,
	}

	addr := "https://quic.tlsfingerprint.io/qfp/?beautify=true"
	// addr := "https://www.cloudflare.com"

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
