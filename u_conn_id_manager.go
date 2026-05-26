package quic

// [UQUIC] SetConnectionIDLimit was previously used to set a custom active connection ID
// limit on the connIDManager. In quic-go v0.59.1, the connIDManager no longer stores
// this limit — it is enforced via protocol.MaxActiveConnectionIDs and the peer's
// transport parameters. This function is kept as a no-op for API compatibility;
// the ActiveConnectionIDLimit value in the transport parameters already controls
// how many connection IDs the server will send us.
func (h *connIDManager) SetConnectionIDLimit(_ uint64) {}
