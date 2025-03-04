package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"

	"github.com/pion/dtls/v3/examples/util"
	quic "github.com/refraction-networking/uquic"
)

func main() {

	var remoteAddr = flag.String("raddr", "127.0.0.1:6666", "remote address")
	// var pubkey = flag.String("secret", "0b63baad7f2f4bb5b547c53adc0fbb179852910607935e6f4b5639fd989b1156", "shared secret")
	var localAddr = flag.String("laddr", "127.0.0.1:6667", "remote address")
	// var covert = flag.String("covert", "1.2.3.4:5678", "covert address")
	flag.Parse()

	laddr, err := net.ResolveUDPAddr("udp", *localAddr)
	util.Check(err)
	addr, err := net.ResolveUDPAddr("udp", *remoteAddr)
	util.Check(err)

	pconn, err := net.ListenUDP("udp", laddr)
	util.Check(err)

	readKey, err := hex.DecodeString("dc079246c2a46f42245546e02bf91ed7d0f3bca91e8b248445f9c39752b011e1")
	util.Check(err)

	writeKey, err := hex.DecodeString("df58c54c3924b0d078377cfe41af7f116dca94e69e3bee6eb28460831bd92dca")
	util.Check(err)

	econn, err := quic.Oscur0Client(pconn, addr, &quic.Oscur0Config{
		ReadKey:      readKey,
		WriteKey:     writeKey,
		ClientConnID: []uint8{1, 2, 3, 4},
		ServerConnID: []uint8{5, 6, 7, 8},
	})
	util.Check(err)

	stream, err := econn.OpenStream()
	util.Check(err)

	fmt.Println("Connected; type 'exit' to shutdown gracefully")

	// Simulate a chat session
	util.Chat(stream)

}
