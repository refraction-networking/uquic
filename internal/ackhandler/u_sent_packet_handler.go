package ackhandler

import "github.com/refraction-networking/uquic/internal/protocol"

type uSentPacketHandler struct {
	*sentPacketHandler

	// initialPacketNumberLength is the PN encoding length for ALL Initial packets.
	// Deprecated: use initialPacketNumberLengths for per-packet control.
	// Ignored when initialPacketNumberLengths is non-empty.
	initialPacketNumberLength protocol.PacketNumberLen // [UQUIC]

	// initialPacketNumberLengths specifies the PN encoding length for each successive
	// Initial packet. Entry [i] applies to the packet with PN = initialPacketNumberBase + i.
	// If the computed index exceeds the slice, the last entry repeats.
	initialPacketNumberLengths []protocol.PacketNumberLen // [UQUIC]

	// initialPacketNumberBase is the PN of the first Initial packet (= InitPacketNumber).
	// Used as the reference point for indexing into initialPacketNumberLengths.
	initialPacketNumberBase protocol.PacketNumber // [UQUIC]
}

func (h *uSentPacketHandler) PeekPacketNumber(encLevel protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen) {
	pnSpace := h.getPacketNumberSpace(encLevel)
	pn := pnSpace.pns.Peek()
	// See section 17.1 of RFC 9000.

	// [UQUIC] Per-packet PN length list takes precedence over single-value override.
	if encLevel == protocol.EncryptionInitial && len(h.initialPacketNumberLengths) > 0 {
		idx := int(pn - h.initialPacketNumberBase)
		if idx < 0 {
			idx = 0
		}
		if idx >= len(h.initialPacketNumberLengths) {
			idx = len(h.initialPacketNumberLengths) - 1
		}
		return pn, h.initialPacketNumberLengths[idx]
	}

	// [UQUIC] Fall back to single-value override for all Initial packets.
	if encLevel == protocol.EncryptionInitial && h.initialPacketNumberLength != 0 {
		return pn, h.initialPacketNumberLength
	}
	// [/UQUIC]

	return pn, protocol.PacketNumberLengthForHeader(pn, pnSpace.largestAcked)
}

// SetInitialPacketNumberLength sets a single PN encoding length used for ALL Initial packets.
// Deprecated: prefer SetInitialPacketNumberLengths for per-packet control.
func SetInitialPacketNumberLength(h SentPacketHandler, pnLen protocol.PacketNumberLen) {
	if sph, ok := h.(*uSentPacketHandler); ok {
		sph.initialPacketNumberLength = pnLen
	}
}

// SetInitialPacketNumberLengths sets per-packet PN encoding lengths for Initial packets.
// base is the PN of the first Initial packet (InitPacketNumber).
// pnLens[0] applies to PN=base, pnLens[1] to PN=base+1, etc.
// If the packet's PN index exceeds len(pnLens), the last entry repeats.
// When set, this overrides any value set by SetInitialPacketNumberLength.
func SetInitialPacketNumberLengths(h SentPacketHandler, base protocol.PacketNumber, pnLens []protocol.PacketNumberLen) {
	if sph, ok := h.(*uSentPacketHandler); ok {
		sph.initialPacketNumberBase = base
		sph.initialPacketNumberLengths = pnLens
	}
}
