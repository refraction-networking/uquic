package protocol

// [UQUIC] MinPacketNumberLen returns the shortest packet number encoding that the
// peer is guaranteed to decode back to pn, given the largest packet number
// acknowledged in pn's packet number space (InvalidPacketNumber if none).
//
// It is a floor for validating a length that a QUICSpec forces, not a length to
// pick: PacketNumberLengthForHeader never goes below 2 bytes, and other stacks
// choose their own (neqo, for one, already uses 2 bytes for packet number 255
// when nothing has been acknowledged).
//
//   - Once a packet in the space is acknowledged, RFC 9000 §17.1: the encoding
//     MUST represent more than twice the distance from the largest acknowledged
//     packet number to pn.
//   - Before that, the peer may not have received any packet of this space and
//     then decodes against an expected packet number of 0 (RFC 9000 Appendix A.3),
//     which recovers pn only if pn itself fits the encoding. Any later receiver
//     state, up to having received pn-1, decodes such a pn correctly as well.
//
// So with nothing acknowledged, packet number 255 fits 1 byte and 256 does not.
func MinPacketNumberLen(pn, largestAcked PacketNumber) PacketNumberLen {
	// span is the number of distinct values the encoding must be able to represent.
	var span PacketNumber
	if largestAcked == InvalidPacketNumber {
		span = pn + 1 // 0 through pn
	} else {
		span = 2*(pn-largestAcked) + 1 // more than twice the distance
	}
	for l := PacketNumberLen1; l < PacketNumberLen4; l++ {
		if span <= PacketNumber(1)<<(8*l) {
			return l
		}
	}
	return PacketNumberLen4
}
