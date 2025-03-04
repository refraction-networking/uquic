package quic

import (
	"context"
	"net"
	"os"

	tls "github.com/refraction-networking/utls"
)

func Oscur0Client(pconn net.PacketConn, addr net.Addr, oscur0Conf *Oscur0Config) (Connection, error) {

	keyLogWriter, err := os.Create("./client_keylog.txt")

	quicSpec, err := QUICID2Spec(QUICFirefox_116)
	if err != nil {
		return nil, err
	}

	tp := UTransport{
		Transport: &Transport{
			Conn: pconn,
		},
		QUICSpec: &quicSpec,
	}

	econn, err := tp.dialOscur0(context.Background(), addr, "", &tls.Config{
		KeyLogWriter: keyLogWriter,
		NextProtos:   []string{"h3"},
	}, &Config{}, false, oscur0Conf)

	if err != nil {
		return nil, err
	}

	return econn, nil
}

var baseServerMap map[string]*baseServer = map[string]*baseServer{}

func Oscur0Server(pconn net.PacketConn, addr net.Addr, oscur0Conf *Oscur0Config) (Connection, error) {
	keyLogWriter, err := os.Create("./server_keylog.txt")
	if err != nil {
		return nil, err
	}

	tp := Transport{
		Conn: pconn,
	}

	server, ok := baseServerMap[pconn.LocalAddr().String()]
	if !ok {
		server, err = tp.createServer(&tls.Config{
			NextProtos:   []string{"h3"},
			KeyLogWriter: keyLogWriter,
		}, &Config{}, true)
		if err != nil {
			return nil, err
		}
		baseServerMap[pconn.LocalAddr().String()] = server
	}

	return server.Oscur0Accept(addr, oscur0Conf)
}

type Oscur0Config struct {
	ReadKey      []byte
	WriteKey     []byte
	ClientConnID []byte
	ServerConnID []byte
}
