package quic

// SetConnectionIDLimit uses the active connection ID limit advertised in the client fingerprint.
func (h *connIDManager) SetConnectionIDLimit(limit uint64) {
	if limit == 0 {
		limit = 2 // RFC 9000 default when active_connection_id_limit is omitted.
	}
	h.connectionIDLimit = limit
}
