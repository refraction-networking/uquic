package quic

import (
	"bytes"
	"errors"
	"fmt"
	"math"

	"github.com/refraction-networking/clienthellod"
	"github.com/refraction-networking/uquic/internal/ackhandler"
	"github.com/refraction-networking/uquic/internal/handshake"
	"github.com/refraction-networking/uquic/internal/monotime"
	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/wire"
	"github.com/refraction-networking/uquic/quicvarint"
)

// uPacketPacker is an extended packetPacker which is used
// to customize some of the packetPacker's behaviors for
// UQUIC.
type uPacketPacker struct {
	*packetPacker

	uSpec *QUICSpec // [UQUIC]

	// initialDatagramIdx tracks how many Initial datagrams have had their payload
	// built via MarshalInitialPacketPayload. Used by QUICFrameBuilderEx to select
	// per-datagram configuration (e.g., different PING/CRYPTO counts per datagram).
	initialDatagramIdx int // [UQUIC]

	// flightPayloads holds the frame payloads a QUICFlightFrameBuilder planned for the
	// Initial datagrams that have not been serialized yet, in flight order. Non-nil only
	// between planInitialFlight and the last datagram of the flight. [UQUIC]
	flightPayloads [][]byte

	// flightPlanned records that BuildFlight has already run, so a flight is planned
	// exactly once per connection — including after flightPayloads has drained. [UQUIC]
	flightPlanned bool
}

func newUPacketPacker(
	packetPacker *packetPacker,
	uSpec *QUICSpec, // [UQUIC]
) *uPacketPacker {
	return &uPacketPacker{
		packetPacker: packetPacker,
		uSpec:        uSpec, // [UQUIC]
	}
}

// PackCoalescedPacket packs a new packet.
// It packs an Initial / Handshake if there is data to send in these packet number spaces.
// It should only be called before the handshake is confirmed.
func (p *uPacketPacker) PackCoalescedPacket(onlyAck bool, maxSize protocol.ByteCount, now monotime.Time, v protocol.Version) (*coalescedPacket, error) {
	var (
		initialHdr, handshakeHdr, zeroRTTHdr                            *wire.ExtendedHeader
		initialPayload, handshakePayload, zeroRTTPayload, oneRTTPayload payload
		oneRTTPacketNumber                                              protocol.PacketNumber
		oneRTTPacketNumberLen                                           protocol.PacketNumberLen
	)
	// Try packing an Initial packet.
	initialSealer, err := p.cryptoSetup.GetInitialSealer()
	if err != nil && err != handshake.ErrKeysDropped {
		return nil, err
	}
	var size protocol.ByteCount
	if initialSealer != nil && !onlyAck {
		// [UQUIC] A QUICFlightFrameBuilder lays out every Initial datagram of the flight
		// in one shot, from the complete CRYPTO stream, before the first one is
		// serialized — the only way a datagram can carry bytes from later in the
		// ClientHello than its own slice. When one is in force it owns the whole Initial
		// flight, so those datagrams bypass the per-datagram pop-and-reframe path below.
		if err := p.planInitialFlight(initialSealer, maxSize, v); err != nil {
			return nil, err
		}
		if len(p.flightPayloads) > 0 {
			return p.packPlannedInitial(initialSealer, v)
		}
	}
	if initialSealer != nil {
		initialMaxSize := maxSize - protocol.ByteCount(initialSealer.Overhead())
		// [UQUIC] Cap the CRYPTO popped for this Initial datagram so the spec can pin the
		// CRYPTO split offset and leave room for PADDING. hdrLen is computed the same way
		// maybeGetCryptoPacket computes it (header Length unset → 1-byte varint), so the
		// budget arithmetic below cancels exactly. Two sources, in priority order:
		//   1. InitialPackets[idx].CryptoLength — an exact per-datagram CRYPTO byte count
		//      (fixes the next datagram's CRYPTO offset; e.g. Chrome splits at 999), or
		//   2. a QUICRandomFrames padding request — reserve a little room so PADDING fits.
		hdrLen := p.getLongHeader(protocol.EncryptionInitial, v).GetLength(v)
		if plan := p.uSpec.InitialPacketSpec.planFor(p.initialDatagramIdx); plan.CryptoLength > 0 {
			off := uint64(p.initialStream.writeOffset)
			cl := protocol.ByteCount(plan.CryptoLength)
			cryptoFrame := 1 + protocol.ByteCount(quicvarint.Len(off)) +
				protocol.ByteCount(quicvarint.Len(uint64(cl))) + cl // type + offset + length + data
			if budget := hdrLen + cryptoFrame; budget > 0 && budget < initialMaxSize {
				initialMaxSize = budget
			}
		} else if rf, ok := p.uSpec.InitialPacketSpec.FrameBuilder.(*QUICRandomFrames); ok && rf.Length > 0 && rf.MinPADDING >= 1 {
			const paddingReserve = 16 // leave at least this many bytes for PADDING frames
			if budget := hdrLen + protocol.ByteCount(rf.Length) - paddingReserve; budget > 0 && budget < initialMaxSize {
				initialMaxSize = budget
			}
		}
		initialHdr, initialPayload = p.maybeGetCryptoPacket(
			initialMaxSize,
			protocol.EncryptionInitial,
			now,
			false,
			onlyAck,
			v,
		)
		if initialPayload.length > 0 {
			size += p.longHeaderPacketLength(initialHdr, initialPayload, v) + protocol.ByteCount(initialSealer.Overhead())
		}
	}

	// Add a Handshake packet.
	var handshakeSealer sealer
	if (onlyAck && size == 0) || (!onlyAck && size < maxSize-protocol.MinCoalescedPacketSize) {
		var err error
		handshakeSealer, err = p.cryptoSetup.GetHandshakeSealer()
		if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
			return nil, err
		}
		if handshakeSealer != nil {
			handshakeHdr, handshakePayload = p.maybeGetCryptoPacket(
				maxSize-size-protocol.ByteCount(handshakeSealer.Overhead()),
				protocol.EncryptionHandshake,
				now,
				false,
				onlyAck,
				v,
			)
			if handshakePayload.length > 0 {
				s := p.longHeaderPacketLength(handshakeHdr, handshakePayload, v) + protocol.ByteCount(handshakeSealer.Overhead())
				size += s
			}
		}
	}

	// Add a 0-RTT / 1-RTT packet.
	var zeroRTTSealer sealer
	var oneRTTSealer handshake.ShortHeaderSealer
	var connID protocol.ConnectionID
	var kp protocol.KeyPhaseBit
	if (onlyAck && size == 0) || (!onlyAck && size < maxSize-protocol.MinCoalescedPacketSize) {
		var err error
		oneRTTSealer, err = p.cryptoSetup.Get1RTTSealer()
		if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
			return nil, err
		}
		if err == nil { // 1-RTT
			kp = oneRTTSealer.KeyPhase()
			connID = p.getDestConnID()
			oneRTTPacketNumber, oneRTTPacketNumberLen = p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
			hdrLen := wire.ShortHeaderLen(connID, oneRTTPacketNumberLen)
			oneRTTPayload = p.maybeGetShortHeaderPacket(oneRTTSealer, hdrLen, maxSize-size, onlyAck, now, v)
			if oneRTTPayload.length > 0 {
				size += p.shortHeaderPacketLength(connID, oneRTTPacketNumberLen, oneRTTPayload) + protocol.ByteCount(oneRTTSealer.Overhead())
			}
		} else if p.perspective == protocol.PerspectiveClient && !onlyAck { // 0-RTT packets can't contain ACK frames
			var err error
			zeroRTTSealer, err = p.cryptoSetup.Get0RTTSealer()
			if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
				return nil, err
			}
			if zeroRTTSealer != nil {
				zeroRTTHdr, zeroRTTPayload = p.maybeGetAppDataPacketFor0RTT(zeroRTTSealer, maxSize-size, now, v)
				if zeroRTTPayload.length > 0 {
					size += p.longHeaderPacketLength(zeroRTTHdr, zeroRTTPayload, v) + protocol.ByteCount(zeroRTTSealer.Overhead())
				}
			}
		}
	}

	if initialPayload.length == 0 && handshakePayload.length == 0 && zeroRTTPayload.length == 0 && oneRTTPayload.length == 0 {
		return nil, nil
	}

	buffer := getPacketBuffer()
	packet := &coalescedPacket{
		buffer:         buffer,
		longHdrPackets: make([]*longHeaderPacket, 0, 3),
	}
	if initialPayload.length > 0 {
		if onlyAck || len(initialPayload.frames) == 0 {
			// TODO: uQUIC should send Initial Packet ACK if requested.
			// However, it should be otherwise configurable whether to request
			// to send Initial Packet ACK or not. See quic-go#4007
			padding := p.initialPaddingLen(initialPayload.frames, size, maxSize)
			cont, err := p.appendLongHeaderPacket(buffer, initialHdr, initialPayload, padding, protocol.EncryptionInitial, initialSealer, v)
			if err != nil {
				return nil, err
			}
			packet.longHdrPackets = append(packet.longHdrPackets, cont)
		} else { // [UQUIC]
			cont, err := p.appendInitialPacket(buffer, initialHdr, initialPayload, protocol.EncryptionInitial, initialSealer, v)
			if err != nil {
				return nil, err
			}

			packet.longHdrPackets = append(packet.longHdrPackets, cont)
		}
	}
	if handshakePayload.length > 0 {
		cont, err := p.appendLongHeaderPacket(buffer, handshakeHdr, handshakePayload, 0, protocol.EncryptionHandshake, handshakeSealer, v)
		if err != nil {
			return nil, err
		}
		packet.longHdrPackets = append(packet.longHdrPackets, cont)
	}
	if zeroRTTPayload.length > 0 {
		longHdrPacket, err := p.appendLongHeaderPacket(buffer, zeroRTTHdr, zeroRTTPayload, 0, protocol.Encryption0RTT, zeroRTTSealer, v)
		if err != nil {
			return nil, err
		}
		packet.longHdrPackets = append(packet.longHdrPackets, longHdrPacket)
	} else if oneRTTPayload.length > 0 {
		shp, err := p.appendShortHeaderPacket(buffer, connID, oneRTTPacketNumber, oneRTTPacketNumberLen, kp, oneRTTPayload, 0, maxSize, oneRTTSealer, false, v)
		if err != nil {
			return nil, err
		}
		packet.shortHdrPacket = &shp
	}
	return packet, nil
}

// [UQUIC]
func (p *uPacketPacker) appendInitialPacket(buffer *packetBuffer, header *wire.ExtendedHeader, pl payload, encLevel protocol.EncryptionLevel, sealer sealer, v protocol.Version) (*longHeaderPacket, error) {
	idx := p.initialDatagramIdx // [UQUIC] capture before MarshalInitialPacketPayload increments it
	uPayload, err := p.MarshalInitialPacketPayload(pl, v)
	if err != nil {
		return nil, err
	}
	return p.appendInitialPacketPayload(buffer, header, pl, uPayload, idx, encLevel, sealer, v)
}

// appendInitialPacketPayload serializes an Initial packet whose frame payload is already
// marshaled: exact-size PADDING, header, AEAD and datagram padding. It is the half of
// appendInitialPacket that a pre-planned flight datagram shares, since a
// QUICFlightFrameBuilder produces uPayload itself. [UQUIC]
func (p *uPacketPacker) appendInitialPacketPayload(buffer *packetBuffer, header *wire.ExtendedHeader, pl payload, uPayload []byte, idx int, encLevel protocol.EncryptionLevel, sealer sealer, v protocol.Version) (*longHeaderPacket, error) {
	pnLen := protocol.ByteCount(header.PacketNumberLen)

	// [UQUIC] Exact-size padding: append PADDING (0x00) bytes to the payload so the
	// serialized Initial packet equals InitialPackets[idx].PacketSize. These bytes are
	// inside the AEAD, so they decode as PADDING frames — unlike the UDPDatagramMinSize
	// trailing zeros, which sit outside the QUIC packet and don't change [Packet Length].
	plan := p.uSpec.InitialPacketSpec.planFor(idx)
	if plan.PacketSize > 0 {
		target := protocol.ByteCount(plan.PacketSize)
		header.Length = target // size the Length varint for the final packet
		cur := header.GetLength(v) + protocol.ByteCount(len(uPayload)) + protocol.ByteCount(sealer.Overhead())
		if target > cur {
			uPayload = append(uPayload, make([]byte, target-cur)...)
		}
	}

	header.Length = pnLen + protocol.ByteCount(sealer.Overhead()) + protocol.ByteCount(len(uPayload))

	startLen := len(buffer.Data)
	// [UQUIC] How many bytes land here is decided by the frame builder and the spec's
	// PacketSize, not by quic-go's payload sizing, so nothing upstream has bounded them
	// against the packet buffer. Writing past it does not just overflow: append() would
	// quietly move raw off buffer.Data's array — losing the packet — and then the reslice
	// below would panic. Refuse the packet with a diagnosable error instead.
	packetLen := int(header.GetLength(v)) + len(uPayload) + sealer.Overhead()
	if avail := cap(buffer.Data) - startLen; packetLen > avail {
		return nil, fmt.Errorf("uquic: Initial packet %d does not fit the packet buffer: %d bytes of frames make a %d-byte packet, %d more than the %d bytes available", idx, len(uPayload), packetLen, packetLen-avail, avail)
	}
	raw := buffer.Data[startLen:] // [UQUIC] the raw here is a sub-slice of buffer.Data, latter's len < size

	raw, err := header.Append(raw, v)
	if err != nil {
		return nil, err
	}
	payloadOffset := protocol.ByteCount(len(raw))
	raw = append(raw, uPayload...)

	raw = p.encryptPacket(raw, sealer, header.PacketNumber, payloadOffset, pnLen)
	buffer.Data = buffer.Data[:len(buffer.Data)+len(raw)]

	// [UQUIC]
	// append zero to buffer.Data until min size is reached. Skipped when this datagram
	// has an exact PacketSize: that size is already achieved with in-payload PADDING, and
	// trailing post-AEAD zeros would push the UDP datagram past the intended packet size.
	if plan.PacketSize == 0 {
		minUDPSize := p.uSpec.UDPDatagramMinSize
		if minUDPSize == 0 {
			minUDPSize = DefaultUDPDatagramMinSize
		}
		if len(buffer.Data) < minUDPSize {
			buffer.Data = append(buffer.Data, make([]byte, minUDPSize-len(buffer.Data))...)
		}
	}

	if pn := p.pnManager.PopPacketNumber(encLevel); pn != header.PacketNumber {
		return nil, fmt.Errorf("packetPacker BUG: Peeked and Popped packet numbers do not match: expected %d, got %d", pn, header.PacketNumber)
	}
	return &longHeaderPacket{
		header:       header,
		ack:          pl.ack,
		frames:       pl.frames,
		streamFrames: pl.streamFrames,
		length:       protocol.ByteCount(len(raw)),
	}, nil
}

// planInitialFlight lays out the entire Initial flight up front, when the spec's
// FrameBuilder is a QUICFlightFrameBuilder. It runs at most once per connection and
// consumes the whole CRYPTO stream, so afterwards the normal per-datagram path finds
// nothing to pop and packPlannedInitial emits the planned datagrams instead. [UQUIC]
func (p *uPacketPacker) planInitialFlight(sealer sealer, maxSize protocol.ByteCount, v protocol.Version) error {
	if p.flightPlanned {
		return nil
	}
	fb, ok := p.uSpec.InitialPacketSpec.FrameBuilder.(QUICFlightFrameBuilder)
	if !ok {
		return nil
	}
	// A flight plan addresses the whole ClientHello, so it can only be made while the
	// CRYPTO stream is untouched and fully queued. uTLS coalesces the ClientHello into a
	// single write event and quic-go drains the handshake events before packing the
	// first packet, so this holds on the first call; if it somehow doesn't, wait rather
	// than cut a flight out of a partial stream.
	if p.initialStream.writeOffset != 0 || !p.initialStream.HasData() {
		return nil
	}
	cryptoData := p.initialStream.PopAllCryptoData()
	if len(cryptoData) == 0 {
		return nil
	}
	p.flightPlanned = true

	budgets := p.flightBudgets(len(cryptoData), sealer, maxSize, v)
	payloads, err := fb.BuildFlight(cryptoData, budgets)
	if err != nil {
		return fmt.Errorf("uquic: BuildFlight: %w", err)
	}
	if err := validateInitialFlight(payloads, budgets, len(cryptoData)); err != nil {
		return err
	}
	p.flightPayloads = payloads
	return nil
}

// flightBudgets describes each Initial datagram to the flight builder. The spec's
// InitialPackets pins the flight length when it is set; otherwise the builder is offered
// as many full-size datagrams as the ClientHello needs. [UQUIC]
func (p *uPacketPacker) flightBudgets(cryptoLen int, sealer sealer, maxSize protocol.ByteCount, v protocol.Version) []InitialDatagramBudget {
	n := len(p.uSpec.InitialPacketSpec.InitialPackets)
	if n == 0 {
		if b := p.initialFrameBudget(maxSize, sealer, v); b > 0 {
			n = (cryptoLen + b - 1) / b
		}
		n = max(n, 1)
	}
	budgets := make([]InitialDatagramBudget, n)
	for i := range budgets {
		plan := p.uSpec.InitialPacketSpec.planFor(i)
		size := maxSize
		if plan.PacketSize > 0 {
			size = protocol.ByteCount(plan.PacketSize)
		}
		budgets[i] = InitialDatagramBudget{Plan: plan, MaxFrameBytes: p.initialFrameBudget(size, sealer, v)}
	}
	return budgets
}

// initialFrameBudget is how many frame payload bytes an Initial packet of exactly
// packetSize bytes can carry: the size minus the long header — with its Length varint
// sized the way appendInitialPacketPayload sizes it — and the AEAD tag. [UQUIC]
func (p *uPacketPacker) initialFrameBudget(packetSize protocol.ByteCount, sealer sealer, v protocol.Version) int {
	hdr := p.getLongHeader(protocol.EncryptionInitial, v)
	hdr.Length = packetSize
	budget := packetSize - hdr.GetLength(v) - protocol.ByteCount(sealer.Overhead())
	return int(max(budget, 0))
}

// validateInitialFlight rejects a plan that cannot be sent as described: a payload too
// large for its datagram, a payload that isn't a valid frame sequence, a CRYPTO frame
// reaching past the end of the stream, or — the failure this whole mechanism exists to
// make impossible — a plan that never emits some of the ClientHello. Nothing else sends
// those bytes, so the peer would collect fragments it can never reassemble. [UQUIC]
func validateInitialFlight(payloads [][]byte, budgets []InitialDatagramBudget, cryptoLen int) error {
	if len(payloads) == 0 {
		return errors.New("uquic: BuildFlight returned no Initial datagrams")
	}
	sent := make([]bool, cryptoLen)
	for i, uPayload := range payloads {
		budget := budgets[min(i, len(budgets)-1)].MaxFrameBytes
		if budget > 0 && len(uPayload) > budget {
			return fmt.Errorf("uquic: BuildFlight: Initial datagram %d is %d bytes of frames, %d more than fits in the packet", i, len(uPayload), len(uPayload)-budget)
		}
		frames, err := clienthellod.ReadAllFrames(bytes.NewReader(uPayload))
		if err != nil {
			return fmt.Errorf("uquic: BuildFlight: Initial datagram %d does not parse as QUIC frames: %w", i, err)
		}
		for _, frame := range frames {
			cf, ok := frame.(*clienthellod.CRYPTO)
			if !ok {
				continue
			}
			if cf.Offset+cf.Length > uint64(cryptoLen) {
				return fmt.Errorf("uquic: BuildFlight: Initial datagram %d has a CRYPTO frame covering [%d,%d) of a %d byte CRYPTO stream", i, cf.Offset, cf.Offset+cf.Length, cryptoLen)
			}
			for j := cf.Offset; j < cf.Offset+cf.Length; j++ {
				sent[j] = true
			}
		}
	}
	for i, ok := range sent {
		if !ok {
			return fmt.Errorf("uquic: BuildFlight: no Initial datagram carries CRYPTO byte %d of %d, so the ClientHello could never be reassembled", i, cryptoLen)
		}
	}
	return nil
}

// packPlannedInitial serializes the next Initial datagram of a pre-planned flight. Such
// a datagram is never coalesced with anything else: the flight builder owns its entire
// frame payload, and no later encryption level is available while the Initial flight is
// still going out. [UQUIC]
func (p *uPacketPacker) packPlannedInitial(sealer sealer, v protocol.Version) (*coalescedPacket, error) {
	uPayload := p.flightPayloads[0]
	p.flightPayloads = p.flightPayloads[1:]
	idx := p.initialDatagramIdx
	p.initialDatagramIdx++

	pl, err := p.plannedInitialPayload(uPayload, v)
	if err != nil {
		return nil, err
	}
	buffer := getPacketBuffer()
	pkt, err := p.appendInitialPacketPayload(buffer, p.getLongHeader(protocol.EncryptionInitial, v), pl, uPayload, idx, protocol.EncryptionInitial, sealer, v)
	if err != nil {
		buffer.Release()
		return nil, err
	}
	return &coalescedPacket{buffer: buffer, longHdrPackets: []*longHeaderPacket{pkt}}, nil
}

// plannedInitialPayload reads the CRYPTO frames back out of a planned payload and
// registers them with the Initial ack handler, so loss recovery retransmits exactly the
// stream ranges this datagram carried rather than the contiguous slice the packer would
// otherwise have popped for it. [UQUIC]
func (p *uPacketPacker) plannedInitialPayload(uPayload []byte, v protocol.Version) (payload, error) {
	frames, err := clienthellod.ReadAllFrames(bytes.NewReader(uPayload))
	if err != nil { // already validated in planInitialFlight, so this is a uQUIC bug
		return payload{}, fmt.Errorf("uquic: planned Initial payload does not parse as QUIC frames: %w", err)
	}
	handler := p.retransmissionQueue.AckHandler(protocol.EncryptionInitial)
	pl := payload{length: protocol.ByteCount(len(uPayload))}
	for _, frame := range frames {
		cf, ok := frame.(*clienthellod.CRYPTO)
		if !ok {
			continue
		}
		pl.frames = append(pl.frames, ackhandler.Frame{
			Frame:   &wire.CryptoFrame{Offset: protocol.ByteCount(cf.Offset), Data: cf.Data()},
			Handler: handler,
		})
	}
	return pl, nil
}

func (p *uPacketPacker) MarshalInitialPacketPayload(pl payload, v protocol.Version) ([]byte, error) {
	// [UQUIC] Once a QUICFlightFrameBuilder has laid out the flight, any further Initial
	// packet is a retransmission or a PTO probe rather than part of it. Its frames can be
	// a non-contiguous set of stream ranges — that freedom is the point of a flight — so
	// they neither reassemble into one slice nor mean anything to a builder that has
	// already planned and consumed the stream. Send them exactly as the packer produced
	// them.
	if p.flightPlanned {
		var frameBytes []byte
		for _, f := range pl.frames {
			var err error
			if frameBytes, err = f.Frame.Append(frameBytes, v); err != nil {
				return nil, err
			}
		}
		return frameBytes, nil
	}

	var originalFrameBytes []byte

	for _, f := range pl.frames {
		var err error
		// only append crypto frames
		if _, ok := f.Frame.(*wire.CryptoFrame); !ok {
			continue
		}

		originalFrameBytes, err = f.Frame.Append(originalFrameBytes, v)
		if err != nil {
			return nil, err
		}
	}

	// extract CryptoData from originalFrameBytes
	// parse frames
	r := bytes.NewReader(originalFrameBytes)
	qchframes, err := clienthellod.ReadAllFrames(r)
	if err != nil {
		return nil, err
	}

	// parse crypto data
	cryptoData, err := clienthellod.ReassembleCRYPTOFrames(qchframes)
	if err != nil {
		return nil, err
	}

	// [UQUIC] Compute baseOffset: the absolute QUIC crypto stream offset of cryptoData[0].
	// For a single-datagram Initial this is always 0. For multi-datagram Initials (e.g.
	// Chrome 146 with X25519MLKEM768, where the ClientHello spans two Initial packets),
	// the second datagram's CRYPTO frames start at the byte after the first datagram's last
	// byte, so baseOffset > 0. Passing this to QUICFrameBuilderEx ensures CRYPTO wire
	// offsets are correct for all N datagrams.
	var baseOffset uint64 = math.MaxUint64
	for _, frame := range qchframes {
		if cf, ok := frame.(*clienthellod.CRYPTO); ok && cf.Offset < baseOffset {
			baseOffset = cf.Offset
		}
	}
	if baseOffset == math.MaxUint64 {
		baseOffset = 0
	}

	// Pass-through path: nil FrameBuilder or empty QUICFrames — preserve original frame layout.
	if qf, ok := p.uSpec.InitialPacketSpec.FrameBuilder.(QUICFrames); p.uSpec.InitialPacketSpec.FrameBuilder == nil || ok && len(qf) == 0 {
		qfs := QUICFrames{}
		for _, frame := range qchframes {
			if cryptoFrame, ok := frame.(*clienthellod.CRYPTO); ok {
				qfs = append(qfs, QUICFrameCrypto{int(cryptoFrame.Offset), int(cryptoFrame.Length)})
			}
		}
		return qfs.Build(cryptoData)
	}

	// [UQUIC] Use QUICFrameBuilderEx if available: supports N-datagram Initials via
	// per-datagram index and base offset. Falls back to Build() for single-datagram specs.
	if ext, ok := p.uSpec.InitialPacketSpec.FrameBuilder.(QUICFrameBuilderEx); ok {
		result, err := ext.BuildForDatagram(p.initialDatagramIdx, cryptoData, baseOffset)
		p.initialDatagramIdx++ // advance after building; each call corresponds to one datagram
		return result, err
	}
	return p.uSpec.InitialPacketSpec.FrameBuilder.Build(cryptoData)
}

func (p *uPacketPacker) PackPTOProbePacket(
	encLevel protocol.EncryptionLevel,
	maxPacketSize protocol.ByteCount,
	addPingIfEmpty bool,
	now monotime.Time,
	v protocol.Version,
) (*coalescedPacket, error) {
	if encLevel == protocol.Encryption1RTT {
		s, err := p.cryptoSetup.Get1RTTSealer()
		if err != nil {
			return nil, err
		}
		kp := s.KeyPhase()
		connID := p.getDestConnID()
		pn, pnLen := p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
		hdrLen := wire.ShortHeaderLen(connID, pnLen)
		pl := p.maybeGetAppDataPacket(maxPacketSize-protocol.ByteCount(s.Overhead())-hdrLen, false, true, now, v)
		if pl.length == 0 {
			return nil, nil
		}
		buffer := getPacketBuffer()
		packet := &coalescedPacket{buffer: buffer}
		shp, err := p.appendShortHeaderPacket(buffer, connID, pn, pnLen, kp, pl, 0, maxPacketSize, s, false, v)
		if err != nil {
			return nil, err
		}
		packet.shortHdrPacket = &shp
		return packet, nil
	}

	var sealer handshake.LongHeaderSealer
	//nolint:exhaustive // Probe packets are never sent for 0-RTT.
	switch encLevel {
	case protocol.EncryptionInitial:
		var err error
		sealer, err = p.cryptoSetup.GetInitialSealer()
		if err != nil {
			return nil, err
		}
	case protocol.EncryptionHandshake:
		var err error
		sealer, err = p.cryptoSetup.GetHandshakeSealer()
		if err != nil {
			return nil, err
		}
	default:
		panic("unknown encryption level")
	}
	hdr, pl := p.maybeGetCryptoPacket(maxPacketSize-protocol.ByteCount(sealer.Overhead()), encLevel, now, addPingIfEmpty, false, v)
	if pl.length == 0 {
		return nil, nil
	}
	buffer := getPacketBuffer()
	packet := &coalescedPacket{buffer: buffer}
	size := p.longHeaderPacketLength(hdr, pl, v) + protocol.ByteCount(sealer.Overhead())
	var padding protocol.ByteCount
	if encLevel == protocol.EncryptionInitial {
		if p.uSpec == nil { // default behavior
			padding = p.initialPaddingLen(pl.frames, size, maxPacketSize)
		} else { // otherwise we resend the spec-based initial packet
			initPkt, err := p.appendInitialPacket(buffer, hdr, pl, protocol.EncryptionInitial, sealer, v)
			if err != nil {
				return nil, err
			}

			packet.longHdrPackets = []*longHeaderPacket{initPkt}
			return packet, nil
		}
	}

	longHdrPacket, err := p.appendLongHeaderPacket(buffer, hdr, pl, padding, encLevel, sealer, v)
	if err != nil {
		return nil, err
	}
	packet.longHdrPackets = []*longHeaderPacket{longHdrPacket}
	return packet, nil
}
