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

	// InitialPackets, when non-empty, pins the per-datagram fragmentation of the
	// Initial flight: entry [i] controls the i-th Initial datagram. This lets a spec
	// reproduce a client whose Initials have specific CRYPTO split offsets and exact
	// wire sizes — e.g. Chrome's X25519MLKEM768 flight of two 1200-byte Initials with
	// the ClientHello split at CRYPTO offset 999:
	//
	//	[]InitialPacketPlan{{CryptoLength: 999, PacketSize: 1200}, {PacketSize: 1200}}
	//
	// If the datagram index exceeds the slice length, the last entry repeats. [UQUIC]
	InitialPackets []InitialPacketPlan
}

// InitialPacketPlan pins, for one Initial datagram, how much of the CRYPTO stream it
// carries and the exact QUIC packet (UDP payload) size it is padded to. See
// InitialPacketSpec.InitialPackets. [UQUIC]
type InitialPacketPlan struct {
	// CryptoLength caps the CRYPTO data bytes placed in this datagram, which fixes
	// the next datagram's CRYPTO offset (the split point). 0 = all remaining CRYPTO.
	CryptoLength int

	// PacketSize forces the exact serialized QUIC packet size (UDP payload bytes) by
	// padding the payload with PADDING frames. 0 = no exact-size padding. Must leave
	// room: the CRYPTO assigned to this datagram (+ header/AEAD) must not exceed it.
	PacketSize int
}

// planFor returns the InitialPacketPlan for datagram index idx (last entry repeats),
// or a zero plan if none is configured.
func (ps *InitialPacketSpec) planFor(idx int) InitialPacketPlan {
	if len(ps.InitialPackets) == 0 {
		return InitialPacketPlan{}
	}
	if idx >= len(ps.InitialPackets) {
		idx = len(ps.InitialPackets) - 1
	}
	return ps.InitialPackets[idx]
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
