package protocol

import "testing"

func TestMinPacketNumberLen(t *testing.T) {
	for _, tc := range []struct {
		pn, largestAcked PacketNumber
		want             PacketNumberLen
	}{
		// Nothing acknowledged: the packet number itself must fit.
		{pn: 0, largestAcked: InvalidPacketNumber, want: PacketNumberLen1},
		{pn: 254, largestAcked: InvalidPacketNumber, want: PacketNumberLen1},
		{pn: 255, largestAcked: InvalidPacketNumber, want: PacketNumberLen1},
		{pn: 256, largestAcked: InvalidPacketNumber, want: PacketNumberLen2},
		{pn: 1<<16 - 1, largestAcked: InvalidPacketNumber, want: PacketNumberLen2},
		{pn: 1 << 16, largestAcked: InvalidPacketNumber, want: PacketNumberLen3},
		{pn: 1<<24 - 1, largestAcked: InvalidPacketNumber, want: PacketNumberLen3},
		{pn: 1 << 24, largestAcked: InvalidPacketNumber, want: PacketNumberLen4},
		// Acknowledged: RFC 9000 §17.1, more than twice the distance.
		{pn: 256, largestAcked: 255, want: PacketNumberLen1},
		{pn: 255 + 127, largestAcked: 255, want: PacketNumberLen1},
		{pn: 255 + 128, largestAcked: 255, want: PacketNumberLen2},
		{pn: 1000 + 1<<15 - 1, largestAcked: 1000, want: PacketNumberLen2},
		{pn: 1000 + 1<<15, largestAcked: 1000, want: PacketNumberLen3},
		{pn: 1000 + 1<<23, largestAcked: 1000, want: PacketNumberLen4},
	} {
		if got := MinPacketNumberLen(tc.pn, tc.largestAcked); got != tc.want {
			t.Errorf("MinPacketNumberLen(%d, %d) = %d, want %d", tc.pn, tc.largestAcked, got, tc.want)
		}
	}
}

// TestMinPacketNumberLenDecodes checks MinPacketNumberLen against the receiver's
// decoder: a packet number encoded in at least MinPacketNumberLen bytes must decode
// back to itself whatever the receiver has already processed, from nothing up to the
// packet just before it. With nothing acknowledged the floor is also tight: one byte
// less, and a receiver that has processed nothing decodes the wrong packet number.
func TestMinPacketNumberLenDecodes(t *testing.T) {
	truncate := func(pn PacketNumber, l PacketNumberLen) PacketNumber {
		return pn & (PacketNumber(1)<<(8*l) - 1)
	}
	for pn := PacketNumber(0); pn < 600; pn++ {
		for _, largestAcked := range []PacketNumber{InvalidPacketNumber, 0, 100, pn - 128, pn - 127, pn - 1} {
			if largestAcked >= pn || (largestAcked < 0 && largestAcked != InvalidPacketNumber) {
				continue
			}
			needed := MinPacketNumberLen(pn, largestAcked)
			// The receiver's largest processed packet number: InvalidPacketNumber per
			// RFC 9000 Appendix A.3, 0 for quic-go's openers, which start there; or
			// anything from the largest acknowledged packet up to pn-1.
			lowest := largestAcked
			if largestAcked == InvalidPacketNumber {
				lowest = 0
				if got := DecodePacketNumber(needed, InvalidPacketNumber, truncate(pn, needed)); got != pn {
					t.Fatalf("pn %d in %d bytes, nothing received: decoded %d", pn, needed, got)
				}
			}
			for rcvd := lowest; rcvd < pn; rcvd++ {
				if got := DecodePacketNumber(needed, rcvd, truncate(pn, needed)); got != pn {
					t.Fatalf("pn %d in %d bytes (largest acked %d), receiver at %d: decoded %d", pn, needed, largestAcked, rcvd, got)
				}
			}
			if largestAcked == InvalidPacketNumber && needed > PacketNumberLen1 {
				shorter := needed - 1
				if got := DecodePacketNumber(shorter, InvalidPacketNumber, truncate(pn, shorter)); got == pn {
					t.Fatalf("pn %d in %d bytes decodes with nothing received, so %d is not the floor", pn, shorter, needed)
				}
			}
		}
	}
}
