package quic

import "github.com/refraction-networking/uquic/internal/protocol"

// [UQUIC] SetConnectionIDLimit makes the connIDManager store as many connection
// IDs as we advertised in our active_connection_id_limit transport parameter.
//
// Upstream quic-go always advertises protocol.MaxActiveConnectionIDs and caps the
// queue at that constant. A uQUIC spec can advertise any value (Firefox sends 8,
// Safari 64), and the peer is entitled to issue that many connection IDs: a
// quic-go server issues min(limit, protocol.MaxIssuedConnectionIDs)-1 new ones
// right after the handshake. Keeping the constant cap would close every such
// connection with CONNECTION_ID_LIMIT_ERROR.
//
// RFC 9000 §18.2 counts the connection ID in use towards the limit. The queue holds
// only the spare connection IDs (the active one is tracked separately), so Add
// rejects a NEW_CONNECTION_ID frame once the queue holds limit connection IDs,
// i.e. once the total would exceed limit. This is the same convention upstream
// applies to protocol.MaxActiveConnectionIDs.
//
// A limit of 0 (no active_connection_id_limit in the spec, or never called)
// keeps upstream's cap of protocol.MaxActiveConnectionIDs.
//
// The connection ID rotation heuristic in shouldUpdateConnID deliberately keeps
// using protocol.MaxActiveConnectionIDs: it decides how many spare connection IDs
// we want before rotating, which does not depend on how many we can store.
func (h *connIDManager) SetConnectionIDLimit(limit uint64) {
	h.activeConnectionIDLimit = limit
}

// [UQUIC] connectionIDLimit returns the maximum number of spare connection IDs
// the queue may hold.
func (h *connIDManager) connectionIDLimit() uint64 {
	if h.activeConnectionIDLimit == 0 {
		return protocol.MaxActiveConnectionIDs
	}
	return h.activeConnectionIDLimit
}
