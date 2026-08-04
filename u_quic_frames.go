package quic

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math"
	"math/big"
	mrand "math/rand"

	"github.com/refraction-networking/clienthellod"
	"github.com/refraction-networking/uquic/quicvarint"
)

// cryptoSafeRandUint64 draws a value from [min, max) with crypto/rand.
//
// A degenerate range [n, n] (or an inverted one) means a fixed value, not a random
// draw — return min directly. crypto/rand.Int panics when its argument is <= 0, so
// this also guards against that crash. This is what lets a spec pin an exact frame
// count, e.g. MinPING==MaxPING==0 for "no PING frames" (Min==Max passes the
// buildInternal bounds checks, which only reject Min>Max).
func cryptoSafeRandUint64(min, max uint64) (uint64, error) {
	if max <= min {
		return min, nil
	}
	minMaxDiff := big.NewInt(int64(max - min))
	offset, err := rand.Int(rand.Reader, minMaxDiff)
	if err != nil {
		return 0, err
	}
	return min + offset.Uint64(), nil
}

// QUICFrameBuilder builds QUIC Initial packet frames from TLS crypto data.
type QUICFrameBuilder interface {
	// Build ingests data from crypto frames without the crypto frame header
	// and returns the byte representation of all frames.
	Build(cryptoData []byte) (allFrames []byte, err error)
}

// QUICFrameBuilderEx extends QUICFrameBuilder with N-datagram support.
// BuildForDatagram is called once per Initial datagram by uPacketPacker:
//   - datagramIdx: 0-based index of this datagram (0 = first Initial packet)
//   - cryptoData: the CRYPTO bytes assigned to this datagram's slice of the crypto stream
//   - baseOffset: absolute QUIC crypto stream offset of cryptoData[0]
//
// Implementations must produce CRYPTO frame wire offsets = (local_offset + baseOffset).
// Existing single-datagram specs (Chrome 115, Firefox 116) implement QUICFrameBuilder
// only; uPacketPacker falls back to Build() when QUICFrameBuilderEx is not implemented.
//
// A datagram can only re-cut the slice it is handed. Slices are popped from the CRYPTO
// stream in order as the flight is packed, so datagram i never sees a byte belonging to
// datagram i+1: with a ~2300-byte ClientHello and ~1150 bytes of Initial payload
// capacity, the tail of the ClientHello does not exist yet when the first datagram is
// built. Every byte handed to BuildForDatagram must also be emitted by it — bytes held
// back are never sent by anyone else, and the ClientHello arrives truncated. Use
// QUICFlightFrameBuilder for any layout that moves bytes between datagrams.
type QUICFrameBuilderEx interface {
	QUICFrameBuilder
	BuildForDatagram(datagramIdx int, cryptoData []byte, baseOffset uint64) (allFrames []byte, err error)
}

// QUICFrames is a slice of QUICFrame that implements QUICFrameBuilder and QUICFrameBuilderEx.
// It could be used to deterministically build QUIC Frames from crypto data.
type QUICFrames []QUICFrame

// Build ingests data from crypto frames without the crypto frame header
// and returns the byte representation of all frames as specified in
// the slice. Equivalent to BuildForDatagram(0, cryptoData, 0).
func (qfs QUICFrames) Build(cryptoData []byte) (payload []byte, err error) {
	return qfs.build(cryptoData, 0)
}

// BuildForDatagram implements QUICFrameBuilderEx.
// baseOffset is added to every CRYPTO frame wire offset, enabling correct
// absolute crypto stream positions for datagrams beyond the first.
func (qfs QUICFrames) BuildForDatagram(_ int, cryptoData []byte, baseOffset uint64) ([]byte, error) {
	return qfs.build(cryptoData, baseOffset)
}

// build is the internal implementation shared by Build and BuildForDatagram.
func (qfs QUICFrames) build(cryptoData []byte, baseOffset uint64) (payload []byte, err error) {
	if len(qfs) == 0 { // If no frames specified, send a single crypto frame
		qfsCryptoOnly := QUICFrames{QUICFrameCrypto{0, 0}}
		return qfsCryptoOnly.build(cryptoData, baseOffset)
	}

	lowestOffset := math.MaxUint16
	for _, frame := range qfs {
		if offset, _, _ := frame.CryptoFrameInfo(); offset < lowestOffset {
			lowestOffset = offset
		}
	}

	for _, frame := range qfs {
		var frameBytes []byte
		if offset, length, cryptoOK := frame.CryptoFrameInfo(); cryptoOK {
			lengthOffset := offset - lowestOffset
			if length == 0 {
				// calculate length: from offset to the end of cryptoData
				length = len(cryptoData) - lengthOffset
			}
			frameBytes = []byte{0x06} // CRYPTO frame type
			// Wire offset = local offset + baseOffset for correct multi-datagram stream positioning.
			wireOffset := uint64(offset) + baseOffset
			frameBytes = quicvarint.Append(frameBytes, wireOffset)
			frameBytes = quicvarint.Append(frameBytes, uint64(length))
			frameCryptoData := make([]byte, length)
			copy(frameCryptoData, cryptoData[lengthOffset:]) // copy at most length bytes
			frameBytes = append(frameBytes, frameCryptoData...)
		} else { // Handle none crypto frames: read and append to payload
			frameBytes, err = frame.Read()
			if err != nil {
				return nil, err
			}
		}
		payload = append(payload, frameBytes...)
	}
	return payload, nil
}

// BuildFromFrames ingests data from all input frames and returns the byte representation
// of all frames as specified in the slice.
func (qfs QUICFrames) BuildFromFrames(frames []byte) (payload []byte, err error) {
	// parse frames
	r := bytes.NewReader(frames)
	qchframes, err := clienthellod.ReadAllFrames(r)
	if err != nil {
		return nil, err
	}

	// parse crypto data
	cryptoData, err := clienthellod.ReassembleCRYPTOFrames(qchframes)
	if err != nil {
		return nil, err
	}

	// marshal
	return qfs.Build(cryptoData)
}

// QUICFrame is the interface for all QUIC frames to be included in the Initial Packet.
type QUICFrame interface {
	// None crypto frames should return false for cryptoOK
	CryptoFrameInfo() (offset, length int, cryptoOK bool)

	// None crypto frames should return the byte representation of the frame.
	// Crypto frames' behavior is undefined and unused.
	Read() ([]byte, error)
}

// QUICFrameCrypto is used to specify the crypto frames containing the TLS ClientHello
// to be sent in the first Initial packet.
type QUICFrameCrypto struct {
	// Offset is used to specify the starting offset of the crypto frame,
	// relative to the start of the crypto data slice for this datagram.
	// Used when sending multiple crypto frames in a single packet.
	//
	// Multiple crypto frames in a single packet must not overlap and must
	// make up an entire crypto stream continuously.
	Offset int

	// Length is used to specify the length of the crypto frame.
	//
	// Must be set if it is NOT the last crypto frame in a packet.
	Length int
}

// CryptoFrameInfo() implements the QUICFrame interface.
//
// Crypto frames are later replaced by the crypto message using the information
// returned by this function.
func (q QUICFrameCrypto) CryptoFrameInfo() (offset, length int, cryptoOK bool) {
	return q.Offset, q.Length, true
}

// Read() implements the QUICFrame interface.
//
// Crypto frames are later replaced by the crypto message, so they are not Read()-able.
func (q QUICFrameCrypto) Read() ([]byte, error) {
	return nil, errors.New("crypto frames are not Read()-able")
}

// QUICFramePadding is used to specify the padding frames to be sent in the first Initial
// packet.
type QUICFramePadding struct {
	// Length is used to specify the length of the padding frame.
	Length int
}

// CryptoFrameInfo() implements the QUICFrame interface.
func (q QUICFramePadding) CryptoFrameInfo() (offset, length int, cryptoOK bool) {
	return 0, 0, false
}

// Read() implements the QUICFrame interface.
//
// Padding simply returns a slice of bytes of the specified length filled with 0.
func (q QUICFramePadding) Read() ([]byte, error) {
	return make([]byte, q.Length), nil
}

// QUICFramePing is used to specify the ping frames to be sent in the first Initial
// packet.
type QUICFramePing struct{}

// CryptoFrameInfo() implements the QUICFrame interface.
func (q QUICFramePing) CryptoFrameInfo() (offset, length int, cryptoOK bool) {
	return 0, 0, false
}

// Read() implements the QUICFrame interface.
//
// Ping simply returns a slice of bytes of size 1 with value 0x01(PING).
func (q QUICFramePing) Read() ([]byte, error) {
	return []byte{0x01}, nil
}

// QUICRandomFrames could be used to indeterministically build QUIC Frames from
// crypto data. A caller may specify how many PING and CRYPTO frames are expected
// to be included in the Initial Packet, as well as the total length plus PADDING
// frames in the end.
//
// QUICRandomFrames implements both QUICFrameBuilder and QUICFrameBuilderEx.
// When used as a FrameBuilder for multi-datagram Initials, each datagram gets
// independently randomized fragmentation with correct absolute CRYPTO offsets.
type QUICRandomFrames struct {
	// MinPING specifies the inclusive lower bound of the number of PING frames to be
	// included in the Initial Packet.
	MinPING uint8

	// MaxPING specifies the exclusive upper bound of the number of PING frames to be
	// included in the Initial Packet. It must be at least MinPING+1.
	MaxPING uint8

	// MinCRYPTO specifies the inclusive lower bound of the number of CRYPTO frames to
	// split the Crypto data into. It must be at least 1.
	MinCRYPTO uint8

	// MaxCRYPTO specifies the exclusive upper bound of the number of CRYPTO frames to
	// split the Crypto data into. It must be at least MinCRYPTO+1.
	MaxCRYPTO uint8

	// MinPADDING specifies the inclusive lower bound of the number of PADDING frames
	// to be included in the Initial Packet. It must be at least 1 if Length is not 0.
	MinPADDING uint8

	// MaxPADDING specifies the exclusive upper bound of the number of PADDING frames
	// to be included in the Initial Packet. It must be at least MinPADDING+1 if
	// Length is not 0.
	MaxPADDING uint8

	// Length specifies the total length of all frames including PADDING frames.
	// If the Length specified is already exceeded by the CRYPTO+PING frames, no
	// PADDING frames will be included.
	Length uint16 // 2 bytes, max 65535
}

// Build ingests data from crypto frames without the crypto frame header
// and returns the byte representation of all frames as specified in
// the slice. Equivalent to BuildForDatagram(0, cryptoData, 0).
func (qrf *QUICRandomFrames) Build(cryptoData []byte) (payload []byte, err error) {
	return qrf.buildInternal(cryptoData, 0)
}

// BuildForDatagram implements QUICFrameBuilderEx.
// datagramIdx is available for future per-datagram configuration (currently ignored;
// all datagrams use the same randomization parameters).
// baseOffset is added to every CRYPTO frame wire offset for correct multi-datagram positioning.
func (qrf *QUICRandomFrames) BuildForDatagram(_ int, cryptoData []byte, baseOffset uint64) ([]byte, error) {
	return qrf.buildInternal(cryptoData, baseOffset)
}

// buildInternal is the shared implementation for Build and BuildForDatagram.
func (qrf *QUICRandomFrames) buildInternal(cryptoData []byte, baseOffset uint64) (payload []byte, err error) {
	// check all bounds
	if qrf.MinPING > qrf.MaxPING {
		return nil, errors.New("MinPING must be less than or equal to MaxPING")
	}
	if qrf.MinCRYPTO < 1 {
		return nil, errors.New("MinCRYPTO must be at least 1")
	}
	if qrf.MinCRYPTO > qrf.MaxCRYPTO {
		return nil, errors.New("MinCRYPTO must be less than or equal to MaxCRYPTO")
	}
	if qrf.MinPADDING < 1 && qrf.Length != 0 {
		return nil, errors.New("MinPADDING must be at least 1 if Length is not 0")
	}
	if qrf.MinPADDING > qrf.MaxPADDING && qrf.Length != 0 {
		return nil, errors.New("MinPADDING must be less than or equal to MaxPADDING if Length is not 0")
	}

	var frameList QUICFrames = make([]QUICFrame, 0)

	// determine number of PING frames with crypto.rand
	numPING, err := cryptoSafeRandUint64(uint64(qrf.MinPING), uint64(qrf.MaxPING))
	if err != nil {
		return nil, err
	}

	// append PING frames
	for i := uint64(0); i < numPING; i++ {
		frameList = append(frameList, QUICFramePing{})
	}

	// determine number of CRYPTO frames with crypto.rand
	numCRYPTO, err := cryptoSafeRandUint64(uint64(qrf.MinCRYPTO), uint64(qrf.MaxCRYPTO))
	if err != nil {
		return nil, err
	}

	lenCryptoData := uint64(len(cryptoData))
	offsetCryptoData := uint64(0)
	// Every CRYPTO frame needs at least one byte, so more frames than bytes is not a
	// layout — clamp instead of underflowing the per-frame budget below.
	numCRYPTO = min(max(numCRYPTO, 1), lenCryptoData)
	for i := uint64(0); i+1 < numCRYPTO; i++ { // select n-1 times, since the last one must be the remaining
		// randomly select length of CRYPTO frame.
		// Length must be at least 1 byte and at most the remaining length of cryptoData minus the remaining number of CRYPTO frames.
		// i.e. len in [1, len(cryptoData)-offsetCryptoData-(numCRYPTO-i-2))
		lenCRYPTO, err := cryptoSafeRandUint64(1, lenCryptoData-(numCRYPTO-i-2))
		if err != nil {
			return nil, err
		}
		frameList = append(frameList, QUICFrameCrypto{Offset: int(offsetCryptoData), Length: int(lenCRYPTO)})
		offsetCryptoData += lenCRYPTO
		lenCryptoData -= lenCRYPTO
	}

	// append the last CRYPTO frame
	frameList = append(frameList, QUICFrameCrypto{Offset: int(offsetCryptoData), Length: 0}) // 0 means the remaining

	// dry-run to determine the total length of all frames so far
	// Use baseOffset=0 for the dry-run since we only care about byte count, not wire offsets.
	dryrunPayload, err := frameList.build(cryptoData, 0)
	if err != nil {
		return nil, err
	}

	// determine length of PADDING frames to append
	lenPADDINGsigned := int64(qrf.Length) - int64(len(dryrunPayload))
	if lenPADDINGsigned > 0 {
		lenPADDING := uint64(lenPADDINGsigned)
		// determine number of PADDING frames to append
		numPADDING, err := cryptoSafeRandUint64(uint64(qrf.MinPADDING), uint64(qrf.MaxPADDING))
		if err != nil {
			return nil, err
		}
		// Every PADDING frame needs at least one byte, so more frames than bytes is not
		// a layout — clamp instead of underflowing the per-frame budget below.
		numPADDING = min(max(numPADDING, 1), lenPADDING)

		for i := uint64(0); i < numPADDING-1; i++ { // select n-1 times, since the last one must be the remaining
			// randomly select length of PADDING frame.
			// Length must be at least 1 byte and at most the remaining length of cryptoData minus the remaining number of CRYPTO frames.
			// i.e. len in [1, lenPADDING-(numPADDING-i-2))
			lenPADDINGFrame, err := cryptoSafeRandUint64(1, lenPADDING-(numPADDING-i-2))
			if err != nil {
				return nil, err
			}
			frameList = append(frameList, QUICFramePadding{Length: int(lenPADDINGFrame)})
			lenPADDING -= lenPADDINGFrame
		}

		// append the last PADDING frame
		frameList = append(frameList, QUICFramePadding{Length: int(lenPADDING)}) // 0 means the remaining
	}

	// shuffle the frameList
	mrand.Shuffle(len(frameList), func(i, j int) {
		frameList[i], frameList[j] = frameList[j], frameList[i]
	})

	// build the payload with the correct base offset for multi-datagram support
	return frameList.build(cryptoData, baseOffset)
}

// QUICMultiDatagramFrames implements QUICFrameBuilderEx with per-datagram configuration.
// It enables different PING/CRYPTO/PADDING distributions for each Initial datagram,
// which is useful for clients like Chrome 146 that send multiple Initial packets.
//
// Each datagram still re-cuts only its own slice of the stream. To choose which part of
// the ClientHello a datagram carries — Chrome's cross-packet CRYPTO scatter, where the
// first datagram holds the tail — use a QUICFlightFrameBuilder instead.
type QUICMultiDatagramFrames struct {
	// PerDatagram specifies the frame randomization for each Initial datagram.
	// PerDatagram[0] is used for the first datagram, [1] for the second, etc.
	// If datagramIdx >= len(PerDatagram), the last entry is used (repeating pattern).
	// Must have at least one entry.
	PerDatagram []QUICRandomFrames
}

// Build implements QUICFrameBuilder by using the first datagram's spec with baseOffset=0.
// This provides backward compatibility when QUICFrameBuilderEx is not used.
func (m *QUICMultiDatagramFrames) Build(cryptoData []byte) ([]byte, error) {
	return m.BuildForDatagram(0, cryptoData, 0)
}

// BuildForDatagram implements QUICFrameBuilderEx.
// It selects the QUICRandomFrames spec for datagramIdx (clamped to the last entry)
// and builds frames with the given baseOffset for correct absolute CRYPTO wire offsets.
func (m *QUICMultiDatagramFrames) BuildForDatagram(datagramIdx int, cryptoData []byte, baseOffset uint64) ([]byte, error) {
	if len(m.PerDatagram) == 0 {
		return nil, errors.New("QUICMultiDatagramFrames: PerDatagram must not be empty")
	}
	idx := datagramIdx
	if idx >= len(m.PerDatagram) {
		idx = len(m.PerDatagram) - 1
	}
	spec := m.PerDatagram[idx]
	return spec.buildInternal(cryptoData, baseOffset)
}
