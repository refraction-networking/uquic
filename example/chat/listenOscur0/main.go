// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net"

	"github.com/pion/dtls/v3/examples/util"
	quic "github.com/refraction-networking/uquic"
)

const (
	receiveMTU      = 8192
	cidSize         = 8
	keySize         = 32
	station_privkey = "203963feed62ddda89b98857940f09866ae840f42e8c90160e411a0029b87e60"
)

type streamConn struct {
	quic.Stream
	quic.Connection
}

func main() {
	var listenAddr = flag.String("laddr", "0.0.0.0:6666", "listen address")
	var remoteAddr = flag.String("raddr", "127.0.0.1:6667", "listen address")

	flag.Parse()

	// Prepare the IP to connect to
	addr, err := net.ResolveUDPAddr("udp", *listenAddr)
	util.Check(err)

	raddr, err := net.ResolveUDPAddr("udp", *remoteAddr)
	util.Check(err)

	priv, err := hex.DecodeString(station_privkey)
	util.Check(err)

	fmt.Printf("%v\n", priv)

	pconn, err := net.ListenUDP("udp", addr)
	util.Check(err)

	// Simulate a chat session
	hub := util.NewHub()

	readKey, err := hex.DecodeString("dc079246c2a46f42245546e02bf91ed7d0f3bca91e8b248445f9c39752b011e1")
	util.Check(err)

	writeKey, err := hex.DecodeString("df58c54c3924b0d078377cfe41af7f116dca94e69e3bee6eb28460831bd92dca")
	util.Check(err)

	go func() {
		// 	for {
		// 		// Wait for a connection.
		econn, err := quic.Oscur0Server(pconn, raddr, &quic.Oscur0Config{
			ReadKey:      readKey,
			WriteKey:     writeKey,
			ClientConnID: []uint8{1, 2, 3, 5, 7},
			ServerConnID: []uint8{5, 6, 7, 9, 10},
		})
		util.Check(err)

		for {

			stream, err := econn.AcceptStream(context.Background())
			if err != nil {
				continue
			}
			// stream, err := econn.OpenStream()
			hub.Register(&streamConn{Stream: stream, Connection: econn})
			return
		}

		// `conn` is of type `net.Conn` but may be casted to `dtls.Conn`
		// using `dtlsConn := conn.(*dtls.Conn)` in order to to expose
		// functions like `ConnectionState` etc.

		// 		// Register the connection with the chat hub
		// 	}
	}()

	// Start chatting
	hub.Chat()
}
