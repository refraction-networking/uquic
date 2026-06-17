package quic

import (
	"crypto/rand"
)

type InitialPacketSpec struct {
	// SrcConnIDLength specifies how many bytes should the SrcConnID be
	SrcConnIDLength int

	// DestConnIDLength specifies how many bytes should the DestConnID be
	DestConnIDLength int

	// InitPacketNumberLength specifies how many bytes should the InitPacketNumber
	// be interpreted as. It is usually 1 or 2 bytes. If unset, UQUIC will use the
	// default algorithm to compute the length which is at least 2 bytes.
	//
	// Deprecated: Use InitPacketNumberLengths for per-packet control. This field is
	// ignored when InitPacketNumberLengths is non-empty.
	InitPacketNumberLength PacketNumberLen

	// InitPacketNumberLengths specifies the PN encoding length for each successive
	// Initial packet. Entry [0] applies to PN=InitPacketNumber, [1] to the next
	// Initial packet, etc. If the packet index exceeds the slice length, the last
	// entry repeats. Overrides InitPacketNumberLength when non-empty.
	//
	// Example (Chrome 146): []PacketNumberLen{1, 2} — 1-byte encoding for PN=1,
	// 2-byte encoding for PN=2.
	InitPacketNumberLengths []PacketNumberLen // [UQUIC]

	// InitPacketNumber is the packet number of the first Initial packet. Following
	// Initial packets, if any, will increment the Packet Number accordingly.
	InitPacketNumber uint64 // [UQUIC]

	// TokenStore is used to store and retrieve tokens. If set, will override the
	// one set in the Config.
	TokenStore TokenStore

	// If ClientTokenLength is set when TokenStore is not set, a dummy TokenStore
	// will be created to randomly generate tokens of the specified length for
	// Pop() calls with any key and silently drop any Put() calls.
	//
	// However, the tokens will not be stored anywhere and are expected to be
	// invalid since not assigned by the server.
	ClientTokenLength int

	// FrameBuilder specifies how the frames should be encapsulated for each Initial
	// packet.
	//
	// If FrameBuilder implements QUICFrameBuilderEx, BuildForDatagram is called once
	// per Initial datagram with the datagram index and base CRYPTO stream offset,
	// enabling correct multi-datagram fingerprinting (e.g. Chrome 146 with two Initials).
	//
	// If nil, there will be only one single Crypto frame in the first Initial packet.
	FrameBuilder QUICFrameBuilder
}

func (ps *InitialPacketSpec) UpdateConfig(conf *Config) {
	conf.TokenStore = ps.getTokenStore()
}

func (ps *InitialPacketSpec) getTokenStore() TokenStore {
	if ps.TokenStore != nil {
		return ps.TokenStore
	}

	if ps.ClientTokenLength > 0 {
		return &dummyTokenStore{
			tokenLength: ps.ClientTokenLength,
		}
	}

	return nil
}

type dummyTokenStore struct {
	tokenLength int
}

func (d *dummyTokenStore) Pop(key string) (token *ClientToken) {
	var data []byte = make([]byte, d.tokenLength)
	rand.Read(data)

	return &ClientToken{
		data: data,
	}
}

func (d *dummyTokenStore) Put(_ string, _ *ClientToken) {
	// Do nothing
}
