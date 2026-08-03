package quic

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	"github.com/refraction-networking/clienthellod"
	"github.com/refraction-networking/uquic/internal/handshake"
	"github.com/refraction-networking/uquic/internal/monotime"
	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// testFlightCryptoLen is a stand-in ClientHello size: two Initial datagrams' worth of
// CRYPTO, so the tail of the stream provably does not exist when datagram 0 is packed.
const testFlightCryptoLen = 2300

// sentCrypto is one CRYPTO frame as it went out on the wire.
type sentCrypto struct {
	offset int
	length int
}

// sentDatagram is one Initial datagram of a flight, as read back off the wire.
type sentDatagram struct {
	packetSize int
	crypto     []sentCrypto
	frameTypes []uint64
}

// packInitialFlight packs Initial datagrams from spec until the packer runs dry, and
// reads each one back off the wire. The mock sealer does not encrypt (it appends its
// overhead verbatim), so the frames parsed here are the frames a peer would see.
func packInitialFlight(t *testing.T, spec *QUICSpec, cryptoData []byte, maxSize protocol.ByteCount) ([]sentDatagram, error) {
	t.Helper()
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	tp.initialStream.DisableScrambling()
	_, err := tp.initialStream.Write(cryptoData)
	require.NoError(t, err)

	tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(1), protocol.PacketNumberLen1).AnyTimes()
	tp.pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(1)).AnyTimes()
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil).AnyTimes()
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable).AnyTimes()
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable).AnyTimes()
	tp.sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable).AnyTimes()
	tp.ackFramer.EXPECT().GetAckFrame(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	up := newUPacketPacker(tp.packer, spec)
	now := monotime.Now()
	var flight []sentDatagram
	for i := 0; i < 16; i++ {
		packet, err := up.PackCoalescedPacket(false, maxSize, now, protocol.Version1)
		if err != nil {
			return flight, err
		}
		if packet == nil {
			break
		}
		flight = append(flight, parseInitialDatagram(t, packet.buffer.Data))
		packet.buffer.Release()
	}
	return flight, nil
}

// parseInitialDatagram reads the frames out of an (unencrypted, in tests) Initial packet.
func parseInitialDatagram(t *testing.T, data []byte) sentDatagram {
	t.Helper()
	hdr, _, _, err := wire.ParsePacket(data)
	require.NoError(t, err)
	extHdr, err := hdr.ParseExtended(data)
	require.NoError(t, err)
	hdrLen := extHdr.GetLength(protocol.Version1)
	packetLen := hdrLen + hdr.Length - protocol.ByteCount(extHdr.PacketNumberLen)
	// The mock sealer appends its overhead to the payload instead of encrypting it.
	payload := data[hdrLen : packetLen-7]

	frames, err := clienthellod.ReadAllFrames(bytes.NewReader(payload))
	require.NoError(t, err)
	dg := sentDatagram{packetSize: int(packetLen)}
	for _, f := range frames {
		dg.frameTypes = append(dg.frameTypes, f.FrameType())
		if cf, ok := f.(*clienthellod.CRYPTO); ok {
			dg.crypto = append(dg.crypto, sentCrypto{offset: int(cf.Offset), length: int(cf.Length)})
		}
	}
	return dg
}

// requireStreamFullySent checks that the flight puts every byte of the CRYPTO stream on
// the wire — the property whose absence leaves the peer with a ClientHello it can never
// reassemble.
func requireStreamFullySent(t *testing.T, flight []sentDatagram, cryptoLen int) {
	t.Helper()
	sent := make([]bool, cryptoLen)
	for _, dg := range flight {
		for _, cf := range dg.crypto {
			require.LessOrEqual(t, cf.offset+cf.length, cryptoLen)
			for i := cf.offset; i < cf.offset+cf.length; i++ {
				sent[i] = true
			}
		}
	}
	for i, ok := range sent {
		require.Truef(t, ok, "CRYPTO byte %d of %d was never sent", i, cryptoLen)
	}
}

func highestCryptoOffset(dg sentDatagram) int {
	highest := -1
	for _, cf := range dg.crypto {
		highest = max(highest, cf.offset+cf.length)
	}
	return highest
}

// TestBuildForDatagramCannotReachTheTail pins the limitation QUICFlightFrameBuilder
// exists to lift: a per-datagram builder is only ever shown the contiguous slice popped
// for its own datagram, so the end of the ClientHello is not in scope for datagram 0 and
// no per-datagram spec can put it there.
func TestBuildForDatagramCannotReachTheTail(t *testing.T) {
	type slice struct {
		idx        int
		baseOffset uint64
		length     int
	}
	var seen []slice
	probe := &frameBuilderFunc{fn: func(idx int, cryptoData []byte, baseOffset uint64) ([]byte, error) {
		seen = append(seen, slice{idx: idx, baseOffset: baseOffset, length: len(cryptoData)})
		return QUICFrames{QUICFrameCrypto{Offset: int(baseOffset), Length: len(cryptoData)}}.buildAbsolute(
			append(make([]byte, baseOffset), cryptoData...))
	}}

	cryptoData := make([]byte, testFlightCryptoLen)
	rand.Read(cryptoData)
	flight, err := packInitialFlight(t, &QUICSpec{
		InitialPacketSpec:  InitialPacketSpec{FrameBuilder: probe},
		UDPDatagramMinSize: 1200,
	}, cryptoData, 1200)
	require.NoError(t, err)

	require.Greater(t, len(seen), 1, "the ClientHello must need more than one datagram")
	require.Zero(t, seen[0].baseOffset)
	require.Less(t, seen[0].length, testFlightCryptoLen,
		"datagram 0 is only handed the slice that fits it, never the whole ClientHello")
	// The bytes datagram 0 could emit end where its slice ends; the tail belongs to a
	// later slice that has not been popped yet.
	require.Less(t, highestCryptoOffset(flight[0]), testFlightCryptoLen)
}

// TestFlightFramesTailInFirstDatagram is the arrangement BuildForDatagram cannot reach:
// the FIRST Initial datagram carries the TAIL of the ClientHello (its highest CRYPTO
// offsets), later datagrams carry the middle.
func TestFlightFramesTailInFirstDatagram(t *testing.T) {
	cryptoData := make([]byte, testFlightCryptoLen)
	rand.Read(cryptoData)

	spec := &QUICSpec{
		InitialPacketSpec: InitialPacketSpec{
			FrameBuilder: &QUICFlightFrames{Datagrams: []QUICFrames{
				{ // the tail, then the head — exactly what a per-datagram builder can't do
					QUICFrameCrypto{Offset: -365},
					QUICFrameCrypto{Offset: 0, Length: 62},
					QUICFramePing{},
				},
				{QUICFrameCrypto{Offset: 62, Length: 1139}},
				{QUICFrameCrypto{Offset: 1201, Length: -365}},
			}},
			InitialPackets: []InitialPacketPlan{{PacketSize: 1200}, {PacketSize: 1200}, {PacketSize: 1200}},
		},
		UDPDatagramMinSize: 1200,
	}
	flight, err := packInitialFlight(t, spec, cryptoData, 1200)
	require.NoError(t, err)
	require.Len(t, flight, 3)

	require.Equal(t, []sentCrypto{{offset: 1935, length: 365}, {offset: 0, length: 62}}, flight[0].crypto)
	require.Equal(t, []sentCrypto{{offset: 62, length: 1139}}, flight[1].crypto)
	require.Equal(t, []sentCrypto{{offset: 1201, length: 734}}, flight[2].crypto)

	// The tail of the ClientHello rides in datagram 1, and it is the highest offset in
	// the whole flight.
	require.Equal(t, testFlightCryptoLen, highestCryptoOffset(flight[0]))
	for _, dg := range flight[1:] {
		require.Less(t, highestCryptoOffset(dg), highestCryptoOffset(flight[0]))
	}
	requireStreamFullySent(t, flight, testFlightCryptoLen)

	// Frame order inside the datagram is preserved, and PacketSize padding still applies.
	require.Equal(t, []uint64{0x06, 0x06, 0x01, 0x00}, flight[0].frameTypes)
	for i, dg := range flight {
		require.Equalf(t, 1200, dg.packetSize, "datagram %d", i)
	}
}

// TestFlightFramesRejectsTruncatedClientHello covers the silent failure this mechanism
// replaces: a plan that never emits part of the stream used to put an unreassemblable
// ClientHello on the wire.
func TestFlightFramesRejectsTruncatedClientHello(t *testing.T) {
	cryptoData := make([]byte, testFlightCryptoLen)
	rand.Read(cryptoData)

	spec := &QUICSpec{
		InitialPacketSpec: InitialPacketSpec{
			FrameBuilder: &QUICFlightFrames{Datagrams: []QUICFrames{
				{QUICFrameCrypto{Offset: 0, Length: 1000}},
				{QUICFrameCrypto{Offset: 1000, Length: 1000}}, // [2000, 2300) never sent
			}},
			InitialPackets: []InitialPacketPlan{{PacketSize: 1200}, {PacketSize: 1200}},
		},
		UDPDatagramMinSize: 1200,
	}
	_, err := packInitialFlight(t, spec, cryptoData, 1200)
	require.ErrorContains(t, err, "no Initial datagram carries CRYPTO byte 2000 of 2300")
}

func TestFlightFramesRejectsOversizedDatagram(t *testing.T) {
	cryptoData := make([]byte, testFlightCryptoLen)
	rand.Read(cryptoData)

	spec := &QUICSpec{
		InitialPacketSpec: InitialPacketSpec{
			FrameBuilder: &QUICFlightFrames{Datagrams: []QUICFrames{
				{QUICFrameCrypto{Offset: 0}}, // the whole ClientHello in one packet
			}},
			InitialPackets: []InitialPacketPlan{{PacketSize: 1200}},
		},
		UDPDatagramMinSize: 1200,
	}
	_, err := packInitialFlight(t, spec, cryptoData, 1200)
	require.ErrorContains(t, err, "more than fits in the packet")
}

func TestFlightFramesRejectsOutOfBoundsRange(t *testing.T) {
	cryptoData := make([]byte, testFlightCryptoLen)
	rand.Read(cryptoData)

	spec := &QUICSpec{
		InitialPacketSpec: InitialPacketSpec{
			FrameBuilder: &QUICFlightFrames{Datagrams: []QUICFrames{
				{QUICFrameCrypto{Offset: 2000, Length: 500}},
			}},
		},
		UDPDatagramMinSize: 1200,
	}
	_, err := packInitialFlight(t, spec, cryptoData, 1200)
	require.ErrorContains(t, err, "out of bounds for a 2300 byte CRYPTO stream")
}

// TestRandomFlightFramesHonoursRanges checks the combination real clients show: which
// part of the ClientHello lands in which datagram is fixed, while the fragmentation
// inside a datagram varies per connection.
func TestRandomFlightFramesHonoursRanges(t *testing.T) {
	cryptoData := make([]byte, testFlightCryptoLen)
	rand.Read(cryptoData)

	newSpec := func() *QUICSpec {
		return &QUICSpec{
			InitialPacketSpec: InitialPacketSpec{
				FrameBuilder: &QUICRandomFlightFrames{PerDatagram: []QUICRandomFlightDatagram{
					{
						CryptoRanges: []QUICCryptoRange{{Offset: -365}, {Offset: 0, Length: 62}},
						Frames:       QUICRandomFrames{MinCRYPTO: 3, MaxCRYPTO: 6, MinPING: 1, MaxPING: 3},
					},
					{
						CryptoRanges: []QUICCryptoRange{{Offset: 62, Length: 1139}},
						Frames:       QUICRandomFrames{MinCRYPTO: 2, MaxCRYPTO: 4},
					},
					{
						CryptoRanges: []QUICCryptoRange{{Offset: 1201, Length: -365}},
						Frames:       QUICRandomFrames{MinCRYPTO: 1, MaxCRYPTO: 3},
					},
				}},
				InitialPackets: []InitialPacketPlan{{PacketSize: 1200}, {PacketSize: 1200}, {PacketSize: 1200}},
			},
			UDPDatagramMinSize: 1200,
		}
	}

	var layouts []string
	for run := 0; run < 8; run++ {
		flight, err := packInitialFlight(t, newSpec(), cryptoData, 1200)
		require.NoError(t, err)
		require.Len(t, flight, 3)
		requireStreamFullySent(t, flight, testFlightCryptoLen)

		// Datagram 1 always carries the tail; the range assignment is the fixed part.
		require.Equal(t, testFlightCryptoLen, highestCryptoOffset(flight[0]))
		for _, cf := range flight[1].crypto {
			require.GreaterOrEqual(t, cf.offset, 62)
			require.LessOrEqual(t, cf.offset+cf.length, 1201)
		}
		for _, cf := range flight[2].crypto {
			require.GreaterOrEqual(t, cf.offset, 1201)
			require.LessOrEqual(t, cf.offset+cf.length, 1935)
		}
		require.GreaterOrEqual(t, len(flight[0].crypto), 6) // 3+ frames for each of 2 ranges

		layouts = append(layouts, flightLayout(flight))
	}
	// The fragmentation is the varying part: eight connections must not all look alike.
	require.Greater(t, len(uniqueStrings(layouts)), 1, "fragmentation did not vary between connections")
}

func TestRandomFlightFramesRejectsGaps(t *testing.T) {
	cryptoData := make([]byte, testFlightCryptoLen)
	rand.Read(cryptoData)

	spec := &QUICSpec{
		InitialPacketSpec: InitialPacketSpec{
			FrameBuilder: &QUICRandomFlightFrames{PerDatagram: []QUICRandomFlightDatagram{
				{CryptoRanges: []QUICCryptoRange{{Offset: 0, Length: 1000}}},
				// [1000, 1100) and [2100, 2300) are never sent
				{CryptoRanges: []QUICCryptoRange{{Offset: 1100, Length: 1000}}},
			}},
			InitialPackets: []InitialPacketPlan{{PacketSize: 1200}, {PacketSize: 1200}},
		},
		UDPDatagramMinSize: 1200,
	}
	_, err := packInitialFlight(t, spec, cryptoData, 1200)
	require.ErrorContains(t, err, "no Initial datagram carries CRYPTO byte 1000 of 2300")
}

// TestFlightFramesDefaultBudgets checks the flight builder still gets usable budgets
// when the spec pins no InitialPackets: one entry per datagram the ClientHello needs.
func TestFlightFramesDefaultBudgets(t *testing.T) {
	cryptoData := make([]byte, testFlightCryptoLen)
	rand.Read(cryptoData)

	var got []InitialDatagramBudget
	spec := &QUICSpec{
		InitialPacketSpec: InitialPacketSpec{
			FrameBuilder: &flightBuilderFunc{fn: func(data []byte, budgets []InitialDatagramBudget) ([][]byte, error) {
				got = budgets
				return (&QUICFlightFrames{Datagrams: []QUICFrames{
					{QUICFrameCrypto{Offset: 0, Length: 1150}},
					{QUICFrameCrypto{Offset: 1150}},
				}}).BuildFlight(data, budgets)
			}},
		},
		UDPDatagramMinSize: 1200,
	}
	flight, err := packInitialFlight(t, spec, cryptoData, 1200)
	require.NoError(t, err)
	require.Len(t, flight, 2)
	require.Len(t, got, 2)
	for _, b := range got {
		require.Greater(t, b.MaxFrameBytes, 1100)
		require.Less(t, b.MaxFrameBytes, 1200)
	}
	requireStreamFullySent(t, flight, testFlightCryptoLen)
}

// frameBuilderFunc adapts a func to QUICFrameBuilderEx.
type frameBuilderFunc struct {
	fn func(datagramIdx int, cryptoData []byte, baseOffset uint64) ([]byte, error)
}

func (b *frameBuilderFunc) Build(cryptoData []byte) ([]byte, error) {
	return b.fn(0, cryptoData, 0)
}

func (b *frameBuilderFunc) BuildForDatagram(idx int, cryptoData []byte, baseOffset uint64) ([]byte, error) {
	return b.fn(idx, cryptoData, baseOffset)
}

// flightBuilderFunc adapts a func to QUICFlightFrameBuilder.
type flightBuilderFunc struct {
	fn func(cryptoData []byte, budgets []InitialDatagramBudget) ([][]byte, error)
}

func (b *flightBuilderFunc) Build(cryptoData []byte) ([]byte, error) {
	payloads, err := b.fn(cryptoData, nil)
	if err != nil {
		return nil, err
	}
	return payloads[0], nil
}

func (b *flightBuilderFunc) BuildFlight(cryptoData []byte, budgets []InitialDatagramBudget) ([][]byte, error) {
	return b.fn(cryptoData, budgets)
}

// flightLayout renders a flight's CRYPTO fragmentation as a comparable string.
func flightLayout(flight []sentDatagram) string {
	var b strings.Builder
	for _, dg := range flight {
		for _, cf := range dg.crypto {
			fmt.Fprintf(&b, "%d+%d,", cf.offset, cf.length)
		}
		b.WriteByte('|')
	}
	return b.String()
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func TestCryptoRangeResolve(t *testing.T) {
	const n = 2300
	for _, tc := range []struct {
		name       string
		r          QUICCryptoRange
		start, end int
		err        string
	}{
		{name: "explicit", r: QUICCryptoRange{Offset: 62, Length: 1139}, start: 62, end: 1201},
		{name: "to the end", r: QUICCryptoRange{Offset: 1201}, start: 1201, end: n},
		{name: "tail from the end", r: QUICCryptoRange{Offset: -365}, start: n - 365, end: n},
		{name: "stopping short of the end", r: QUICCryptoRange{Offset: 1201, Length: -365}, start: 1201, end: n - 365},
		{name: "whole stream", r: QUICCryptoRange{}, start: 0, end: n},
		{name: "offset past the end", r: QUICCryptoRange{Offset: n + 1}, err: "out of bounds"},
		{name: "offset before the start", r: QUICCryptoRange{Offset: -(n + 1)}, err: "out of bounds"},
		{name: "length past the end", r: QUICCryptoRange{Offset: 2000, Length: 400}, err: "out of bounds"},
		{name: "end before start", r: QUICCryptoRange{Offset: 2000, Length: -400}, err: "out of bounds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start, end, err := tc.r.resolve(n)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.start, start)
			require.Equal(t, tc.end, end)
		})
	}
}

// TestPostFlightInitialRetransmission covers the Initial packets that come after the
// planned flight — a PTO probe, or a retransmission of a datagram whose CRYPTO ranges
// were not contiguous. They must not be routed back through the flight builder, whose
// stream is already consumed.
func TestPostFlightInitialRetransmission(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	tp.initialStream.DisableScrambling()
	cryptoData := make([]byte, testFlightCryptoLen)
	rand.Read(cryptoData)
	_, err := tp.initialStream.Write(cryptoData)
	require.NoError(t, err)

	tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(1), protocol.PacketNumberLen1).AnyTimes()
	tp.pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(1)).AnyTimes()
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil).AnyTimes()
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable).AnyTimes()
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable).AnyTimes()
	tp.sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable).AnyTimes()
	tp.ackFramer.EXPECT().GetAckFrame(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	up := newUPacketPacker(tp.packer, &QUICSpec{
		InitialPacketSpec: InitialPacketSpec{
			FrameBuilder: &QUICFlightFrames{Datagrams: []QUICFrames{
				{QUICFrameCrypto{Offset: -365}, QUICFrameCrypto{Offset: 0, Length: 62}},
				{QUICFrameCrypto{Offset: 62, Length: 1138}},
				{QUICFrameCrypto{Offset: 1200, Length: -365}},
			}},
			InitialPackets: []InitialPacketPlan{{PacketSize: 1200}, {PacketSize: 1200}, {PacketSize: 1200}},
		},
		UDPDatagramMinSize: 1200,
	})

	now := monotime.Now()
	for i := 0; i < 3; i++ {
		packet, err := up.PackCoalescedPacket(false, 1200, now, protocol.Version1)
		require.NoError(t, err)
		require.NotNil(t, packet)
		packet.buffer.Release()
	}
	// The flight is out; nothing is left to pack.
	packet, err := up.PackCoalescedPacket(false, 1200, now, protocol.Version1)
	require.NoError(t, err)
	require.Nil(t, packet)

	// Datagram 1's ranges were not contiguous. Losing it re-queues both, and the
	// retransmission must still serialize.
	tp.retransmissionQueue.addInitial(&wire.CryptoFrame{Offset: testFlightCryptoLen - 365, Data: cryptoData[testFlightCryptoLen-365:]})
	tp.retransmissionQueue.addInitial(&wire.CryptoFrame{Offset: 0, Data: cryptoData[:62]})
	packet, err = up.PackCoalescedPacket(false, 1200, now, protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, packet)
	dg := parseInitialDatagram(t, packet.buffer.Data)
	require.Equal(t, []sentCrypto{{offset: testFlightCryptoLen - 365, length: 365}, {offset: 0, length: 62}}, dg.crypto)
	packet.buffer.Release()

	// A PTO probe with nothing left to send is a PING, not an error.
	probe, err := up.PackPTOProbePacket(protocol.EncryptionInitial, 1200, true, now, protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, probe)
	require.Equal(t, []uint64{0x01, 0x00}, parseInitialDatagram(t, probe.buffer.Data).frameTypes)
	probe.buffer.Release()
}
