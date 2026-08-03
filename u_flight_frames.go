package quic

import (
	"errors"
	"fmt"
	mrand "math/rand"

	"github.com/refraction-networking/uquic/quicvarint"
)

// QUICFlightFrameBuilder builds the frame payload of every Initial datagram in the
// flight at once, from the complete CRYPTO stream.
//
// It exists because QUICFrameBuilderEx cannot describe a flight. BuildForDatagram is
// handed only the contiguous slice of the CRYPTO stream the packer popped for that one
// datagram, and slices are popped in stream order as the flight is packed, so no
// datagram can carry bytes from later in the ClientHello than its own slice. Real
// clients do exactly that: Chrome's Initial flight puts the TAIL of the ClientHello (its
// highest CRYPTO offsets) in the FIRST datagram and the middle of the ClientHello in
// later ones. With a ~2300-byte ClientHello and ~1150 bytes of Initial payload capacity,
// those tail bytes have not even been produced when datagram 0 is built.
//
// BuildFlight closes that gap. It is called once, before any Initial packet of the
// flight is serialized, with the entire CRYPTO stream, and returns the exact frame
// payload of every Initial datagram. Any byte range may be placed in any datagram, in
// any order. uQUIC supplies only the long header, packet number, token, exact-size
// PADDING and AEAD.
//
// QUICFlightFrames and QUICRandomFlightFrames implement this; a caller needing something
// neither expresses can implement it directly.
type QUICFlightFrameBuilder interface {
	QUICFrameBuilder

	// BuildFlight returns one frame payload per Initial datagram, in flight order.
	// budgets[i] describes datagram i; len(budgets) is what the spec asked for, but the
	// length of the returned slice decides how many Initial datagrams are actually sent.
	//
	// Every byte of cryptoData must be covered by a CRYPTO frame somewhere in the
	// returned payloads. A byte no datagram emits is never sent by anything else, and
	// the peer sees a ClientHello it can never reassemble; uQUIC rejects such a plan
	// instead of putting it on the wire.
	BuildFlight(cryptoData []byte, budgets []InitialDatagramBudget) (payloads [][]byte, err error)
}

// InitialDatagramBudget tells a QUICFlightFrameBuilder what one Initial datagram of the
// flight can hold. [UQUIC]
type InitialDatagramBudget struct {
	// Plan is the InitialPacketPlan the spec pinned for this datagram, or the zero plan
	// if InitialPacketSpec.InitialPackets doesn't reach this far.
	Plan InitialPacketPlan

	// MaxFrameBytes is the largest frame payload this datagram can carry: its QUIC
	// packet size (Plan.PacketSize, or the path MTU when that is unset) minus the long
	// header and the AEAD tag. A longer payload cannot be sent and is rejected.
	MaxFrameBytes int
}

// QUICCryptoRange is a byte range of the complete CRYPTO stream — the serialized
// ClientHello — addressed by absolute position rather than by position within whatever
// slice a single datagram was handed. [UQUIC]
type QUICCryptoRange struct {
	// Offset is the absolute offset of the first byte. A negative Offset counts back
	// from the end of the stream, so Offset: -365 is "the last 365 bytes". That is how
	// to pin "this datagram carries the tail of the ClientHello" without knowing the
	// ClientHello's exact length, which shifts whenever the TLS spec changes.
	Offset int

	// Length is the number of bytes. 0 means "to the end of the stream", and a negative
	// Length ends the range that many bytes before the end (-365 stops where a
	// {Offset: -365} tail range begins). Between the two, a flight can be described
	// entirely in offsets from the start and the end, and stays correct when the
	// ClientHello's length shifts.
	Length int
}

// resolve turns r into concrete [start, end) bounds within a streamLen-byte stream.
func (r QUICCryptoRange) resolve(streamLen int) (start, end int, err error) {
	start = r.Offset
	if start < 0 {
		start = streamLen + start
	}
	if start < 0 || start > streamLen {
		return 0, 0, fmt.Errorf("CRYPTO range offset %d is out of bounds for a %d byte CRYPTO stream", r.Offset, streamLen)
	}
	if r.Length > 0 {
		end = start + r.Length
	} else {
		end = streamLen + r.Length // 0 = to the end, negative = that far short of it
	}
	if end > streamLen || end < start {
		return 0, 0, fmt.Errorf("CRYPTO range [%d,%d) is out of bounds for a %d byte CRYPTO stream", start, end, streamLen)
	}
	return start, end, nil
}

// QUICFlightFrames is a declarative QUICFlightFrameBuilder that pins the exact frame
// layout of every Initial datagram in the flight.
//
// Datagrams[i] is the wire-order frame list of Initial datagram i. It reuses QUICFrames,
// with one difference that is the whole point of a flight plan: a QUICFrameCrypto's
// Offset is an ABSOLUTE offset into the complete CRYPTO stream, not an offset into the
// slice this datagram happened to be handed. Offset and Length are read as a
// QUICCryptoRange, so both may be negative to address the stream from its end.
// QUICFramePing and QUICFramePadding behave exactly as they do elsewhere.
//
// Chrome's three-datagram flight — tail first, then the head, then the middle:
//
//	QUICFlightFrames{Datagrams: []QUICFrames{
//	    {QUICFrameCrypto{Offset: -365}, QUICFrameCrypto{Offset: 0, Length: 62}},
//	    {QUICFrameCrypto{Offset: 62, Length: 1139}},
//	    {QUICFrameCrypto{Offset: 1201, Length: -365}}, // up to where the tail starts
//	}}
//
// The layout is fixed, so every connection emits the same one. Real clients vary their
// fragmentation per connection; use QUICRandomFlightFrames when that variation is itself
// part of the fingerprint. [UQUIC]
type QUICFlightFrames struct {
	// Datagrams[i] is the ordered frame list of Initial datagram i. Must not be empty.
	Datagrams []QUICFrames
}

// Build implements QUICFrameBuilder by building the first datagram's frames. It is the
// fallback used for Initial packets outside the planned flight (e.g. a PTO probe that
// retransmits CRYPTO after the flight is gone).
func (f *QUICFlightFrames) Build(cryptoData []byte) ([]byte, error) {
	if len(f.Datagrams) == 0 {
		return nil, errors.New("QUICFlightFrames: Datagrams must not be empty")
	}
	return f.Datagrams[0].buildAbsolute(cryptoData)
}

// BuildFlight implements QUICFlightFrameBuilder.
func (f *QUICFlightFrames) BuildFlight(cryptoData []byte, _ []InitialDatagramBudget) ([][]byte, error) {
	if len(f.Datagrams) == 0 {
		return nil, errors.New("QUICFlightFrames: Datagrams must not be empty")
	}
	payloads := make([][]byte, 0, len(f.Datagrams))
	for i, frames := range f.Datagrams {
		payload, err := frames.buildAbsolute(cryptoData)
		if err != nil {
			return nil, fmt.Errorf("Initial datagram %d: %w", i, err)
		}
		payloads = append(payloads, payload)
	}
	return payloads, nil
}

// buildAbsolute serializes a frame list whose QUICFrameCrypto offsets address
// fullCrypto — the complete CRYPTO stream — directly, so each CRYPTO frame's wire offset
// is its declared offset. Contrast QUICFrames.build, which reads offsets as positions
// within one datagram's slice and rebases them onto the stream.
func (qfs QUICFrames) buildAbsolute(fullCrypto []byte) ([]byte, error) {
	var payload []byte
	for _, frame := range qfs {
		offset, length, isCrypto := frame.CryptoFrameInfo()
		if !isCrypto {
			frameBytes, err := frame.Read()
			if err != nil {
				return nil, err
			}
			payload = append(payload, frameBytes...)
			continue
		}
		start, end, err := QUICCryptoRange{Offset: offset, Length: length}.resolve(len(fullCrypto))
		if err != nil {
			return nil, err
		}
		payload = append(payload, 0x06) // CRYPTO frame type
		payload = quicvarint.Append(payload, uint64(start))
		payload = quicvarint.Append(payload, uint64(end-start))
		payload = append(payload, fullCrypto[start:end]...)
	}
	return payload, nil
}

// QUICRandomFlightFrames is a QUICFlightFrameBuilder that assigns each Initial datagram
// an explicit set of absolute CRYPTO ranges — which is what a per-datagram builder
// cannot do — and then randomizes the framing *within* each datagram per connection, the
// way QUICRandomFrames does within a single packet.
//
// This is the combination real clients show: which part of the ClientHello lands in
// which datagram is a fixed structural property of the client (Chrome always carries the
// tail in datagram 1), while the cut points, frame order and PADDING placement inside a
// datagram differ on every connection. A fingerprinter reads the first as a signature
// and the second as noise, so reproducing only the fixed half — the same fragmentation
// on every connection — is itself a tell.
//
//	QUICRandomFlightFrames{PerDatagram: []QUICRandomFlightDatagram{
//	    {   // datagram 1: the tail, then the head, scattered into 6-9 CRYPTO frames
//	        CryptoRanges: []QUICCryptoRange{{Offset: -365}, {Offset: 0, Length: 62}},
//	        Frames:       QUICRandomFrames{MinCRYPTO: 3, MaxCRYPTO: 5, MinPING: 1, MaxPING: 3},
//	    },
//	    {   // datagram 2: the contiguous middle
//	        CryptoRanges: []QUICCryptoRange{{Offset: 62, Length: 1139}},
//	        Frames:       QUICRandomFrames{MinCRYPTO: 1, MaxCRYPTO: 2},
//	    },
//	}}
//
// [UQUIC]
type QUICRandomFlightFrames struct {
	// PerDatagram[i] describes Initial datagram i. Must not be empty.
	PerDatagram []QUICRandomFlightDatagram
}

// QUICRandomFlightDatagram is one Initial datagram of a QUICRandomFlightFrames plan.
// [UQUIC]
type QUICRandomFlightDatagram struct {
	// CryptoRanges are the absolute ranges of the CRYPTO stream this datagram carries.
	// Any range may go in any datagram — that freedom is the reason this type exists.
	// Across the whole flight the ranges must cover the entire stream, or uQUIC rejects
	// the plan rather than sending a ClientHello that can never be reassembled.
	CryptoRanges []QUICCryptoRange

	// Frames randomizes this datagram's framing. Each range in CryptoRanges is
	// independently cut into [MinCRYPTO, MaxCRYPTO) CRYPTO frames, [MinPING, MaxPING)
	// PING frames are added, the whole list is shuffled, and PADDING is appended to
	// reach Frames.Length (which, unlike InitialPacketPlan.PacketSize, can be scattered
	// through the packet rather than trailing it). The zero value emits exactly one
	// CRYPTO frame per range, in order, with no PING or PADDING.
	Frames QUICRandomFrames
}

// Build implements QUICFrameBuilder by laying out the first datagram against cryptoData
// as if it were the whole stream. Used for Initial packets outside the planned flight.
func (f *QUICRandomFlightFrames) Build(cryptoData []byte) ([]byte, error) {
	if len(f.PerDatagram) == 0 {
		return nil, errors.New("QUICRandomFlightFrames: PerDatagram must not be empty")
	}
	return f.PerDatagram[0].build(cryptoData)
}

// BuildFlight implements QUICFlightFrameBuilder.
func (f *QUICRandomFlightFrames) BuildFlight(cryptoData []byte, _ []InitialDatagramBudget) ([][]byte, error) {
	if len(f.PerDatagram) == 0 {
		return nil, errors.New("QUICRandomFlightFrames: PerDatagram must not be empty")
	}
	payloads := make([][]byte, 0, len(f.PerDatagram))
	for i, dg := range f.PerDatagram {
		payload, err := dg.build(cryptoData)
		if err != nil {
			return nil, fmt.Errorf("Initial datagram %d: %w", i, err)
		}
		payloads = append(payloads, payload)
	}
	return payloads, nil
}

// build lays out one datagram: cut each assigned range into random CRYPTO frames, add
// PING frames, shuffle, then pad up to Frames.Length.
func (d *QUICRandomFlightDatagram) build(fullCrypto []byte) ([]byte, error) {
	if len(d.CryptoRanges) == 0 {
		return nil, errors.New("CryptoRanges must not be empty")
	}
	rf := &d.Frames
	if rf.MinCRYPTO > rf.MaxCRYPTO {
		return nil, errors.New("MinCRYPTO must be less than or equal to MaxCRYPTO")
	}
	if rf.MinPING > rf.MaxPING {
		return nil, errors.New("MinPING must be less than or equal to MaxPING")
	}
	if rf.Length != 0 {
		if rf.MinPADDING < 1 {
			return nil, errors.New("MinPADDING must be at least 1 if Length is not 0")
		}
		if rf.MinPADDING > rf.MaxPADDING {
			return nil, errors.New("MinPADDING must be less than or equal to MaxPADDING if Length is not 0")
		}
	}

	var frameList QUICFrames
	for _, r := range d.CryptoRanges {
		start, end, err := r.resolve(len(fullCrypto))
		if err != nil {
			return nil, err
		}
		if end <= start {
			continue // an empty range carries nothing; a CRYPTO frame for it would be noise
		}
		pieces, err := splitRange(start, end, uint64(max(rf.MinCRYPTO, 1)), uint64(max(rf.MaxCRYPTO, 1)))
		if err != nil {
			return nil, err
		}
		frameList = append(frameList, pieces...)
	}
	if len(frameList) == 0 {
		return nil, errors.New("CryptoRanges cover no bytes of the CRYPTO stream")
	}

	numPING, err := cryptoSafeRandUint64(uint64(rf.MinPING), uint64(rf.MaxPING))
	if err != nil {
		return nil, err
	}
	for i := uint64(0); i < numPING; i++ {
		frameList = append(frameList, QUICFramePing{})
	}

	// Measure what we have so far, then top up to Length with PADDING frames.
	dryrun, err := frameList.buildAbsolute(fullCrypto)
	if err != nil {
		return nil, err
	}
	if lenPADDING := int64(rf.Length) - int64(len(dryrun)); lenPADDING > 0 {
		numPADDING, err := cryptoSafeRandUint64(uint64(rf.MinPADDING), uint64(rf.MaxPADDING))
		if err != nil {
			return nil, err
		}
		remaining := uint64(lenPADDING)
		// Every PADDING frame needs at least one byte, so more frames than bytes is not
		// a layout — clamp instead of underflowing the per-frame budget below.
		numPADDING = min(max(numPADDING, 1), remaining)
		for i := uint64(0); i+1 < numPADDING; i++ {
			n, err := cryptoSafeRandUint64(1, remaining-(numPADDING-i-2))
			if err != nil {
				return nil, err
			}
			frameList = append(frameList, QUICFramePadding{Length: int(n)})
			remaining -= n
		}
		frameList = append(frameList, QUICFramePadding{Length: int(remaining)})
	}

	mrand.Shuffle(len(frameList), func(i, j int) {
		frameList[i], frameList[j] = frameList[j], frameList[i]
	})
	return frameList.buildAbsolute(fullCrypto)
}

// splitRange cuts [start, end) into a random number of CRYPTO frames in [minN, maxN),
// each at least one byte, and returns them in ascending offset order. Offsets are
// absolute, so the caller may shuffle the result freely.
func splitRange(start, end int, minN, maxN uint64) (QUICFrames, error) {
	n, err := cryptoSafeRandUint64(minN, maxN)
	if err != nil {
		return nil, err
	}
	n = min(max(n, 1), uint64(end-start)) // at least one frame, at most one byte per frame

	frames := make(QUICFrames, 0, n)
	off := start
	for i := uint64(0); i+1 < n; i++ {
		// Leave at least one byte for each of the frames that still have to be cut.
		remainingFrames := int(n - i - 1)
		length, err := cryptoSafeRandUint64(1, uint64(end-off-remainingFrames+1))
		if err != nil {
			return nil, err
		}
		frames = append(frames, QUICFrameCrypto{Offset: off, Length: int(length)})
		off += int(length)
	}
	return append(frames, QUICFrameCrypto{Offset: off, Length: end - off}), nil
}
