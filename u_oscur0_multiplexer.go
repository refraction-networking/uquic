package quic

// We disable the multiplexer as oscur0 uses its own multiplexer.
func getMultiplexer() multiplexer {
	return &oscur0Multiplexer{}
}

type oscur0Multiplexer struct{}

func (*oscur0Multiplexer) AddConn(c indexableConn) {}

func (*oscur0Multiplexer) RemoveConn(c indexableConn) error { return nil }
