package quic

import (
	"bytes"
	"testing"

	"github.com/refraction-networking/clienthellod"
)

func TestQUICFrames(t *testing.T) {
	resultQUICPayload, err := testQUICFrames.Build(testCryptoFrameBytes)
	if err != nil {
		t.Fatalf("Failed to build QUIC frames: %v", err)
	}

	if len(resultQUICPayload) != len(truthPayloadFromQUICFrames) {
		t.Fatalf("QUIC payload length mismatch: got %d, want %d. \n%x", len(resultQUICPayload), len(truthPayloadFromQUICFrames), resultQUICPayload)
	}

	// verify that the crypto frames would actually assemble the original crypto data
	r := bytes.NewReader(resultQUICPayload)
	qchframes, err := clienthellod.ReadAllFrames(r)
	if err != nil {
		t.Fatalf("Failed to read QUIC frames: %v", err)
	}

	reassembledCryptoData, err := clienthellod.ReassembleCRYPTOFrames(qchframes)
	if err != nil {
		t.Fatalf("Failed to reassemble crypto data: %v", err)
	}
	if !bytes.Equal(reassembledCryptoData, testCryptoFrameBytes) {
		t.Fatalf("Reassembled crypto data mismatch: \n%x", reassembledCryptoData)
	}
}

func TestQUICRandomFrames(t *testing.T) {
	resultQUICPayload, err := testQUICRandomFrames.Build(testCryptoFrameBytes)
	if err != nil {
		t.Fatalf("Failed to build QUIC frames: %v", err)
	}

	if len(resultQUICPayload) != 512 {
		t.Fatalf("QUIC payload length mismatch: got %d, want 512. \n%x", len(resultQUICPayload), resultQUICPayload)
	}

	// verify that the crypto frames would actually assemble the original crypto data
	r := bytes.NewReader(resultQUICPayload)
	qchframes, err := clienthellod.ReadAllFrames(r)
	if err != nil {
		t.Fatalf("Failed to read QUIC frames: %v", err)
	}

	reassembledCryptoData, err := clienthellod.ReassembleCRYPTOFrames(qchframes)
	if err != nil {
		t.Fatalf("Failed to reassemble crypto data: %v", err)
	}
	if !bytes.Equal(reassembledCryptoData, testCryptoFrameBytes) {
		t.Fatalf("Reassembled crypto data mismatch: \n%x", reassembledCryptoData)
	}

	// count how many PING and CRYPTO frames are in the QUIC payload
	var pingCount, cryptoCount int
	for _, frame := range qchframes {
		switch frame.FrameType() {
		case clienthellod.QUICFrame_PING:
			pingCount++
		case clienthellod.QUICFrame_CRYPTO:
			cryptoCount++
		}
	}

	if pingCount < 2 || pingCount > 8 {
		t.Fatalf("PING frame count mismatch: got %d, want 2-8", pingCount)
	}

	if cryptoCount < 2 || cryptoCount > 8 {
		t.Fatalf("CRYPTO frame count mismatch: got %d, want 2-8", cryptoCount)
	}
}

// TestQUICRandomFramesMorePADDINGFramesThanBytes pins the case where the spec asks for
// more PADDING frames than there are PADDING bytes to hand out. Every PADDING frame needs
// at least one byte, so the frame count must be clamped to the byte budget; without the
// clamp the per-frame budget underflows (unsigned) and the payload blows past Length.
func TestQUICRandomFramesMorePADDINGFramesThanBytes(t *testing.T) {
	// Pin PING/CRYPTO to one frame each (min == max is not random) and measure the
	// CRYPTO+PING size with padding disabled, so we can ask for a known few bytes of it.
	base := QUICRandomFrames{
		MinPING:   1,
		MaxPING:   1,
		MinCRYPTO: 1,
		MaxCRYPTO: 1,
		Length:    0, // already exceeded by CRYPTO+PING, so no PADDING is appended
	}
	basePayload, err := base.Build(testCryptoFrameBytes)
	if err != nil {
		t.Fatalf("Failed to build baseline QUIC frames: %v", err)
	}

	for extra := 1; extra <= 8; extra++ {
		qrf := base
		qrf.MinPADDING = 6 // more PADDING frames than the extra bytes available
		qrf.MaxPADDING = 6
		qrf.Length = uint16(len(basePayload) + extra)

		resultQUICPayload, err := qrf.Build(testCryptoFrameBytes)
		if err != nil {
			t.Fatalf("Failed to build QUIC frames with %d PADDING bytes: %v", extra, err)
		}

		if len(resultQUICPayload) != int(qrf.Length) {
			t.Fatalf("QUIC payload length mismatch with %d PADDING bytes: got %d, want %d",
				extra, len(resultQUICPayload), qrf.Length)
		}
	}
}

// TestQUICRandomFramesMoreCRYPTOFramesThanBytes is the CRYPTO analogue of the PADDING
// case above: a spec that asks to split the crypto data into more CRYPTO frames than it
// has bytes. Each frame carries at least one byte, so the count must be clamped to the
// data available; without the clamp the per-frame budget underflows.
func TestQUICRandomFramesMoreCRYPTOFramesThanBytes(t *testing.T) {
	shortCryptoData := []byte{0xde, 0xad, 0xbe}

	qrf := QUICRandomFrames{
		MinPING:   0, // min == max is not random, so this pins "no PING frames"
		MaxPING:   0,
		MinCRYPTO: 6, // more CRYPTO frames than the 3 bytes there are to split
		MaxCRYPTO: 6,
	}
	resultQUICPayload, err := qrf.Build(shortCryptoData)
	if err != nil {
		t.Fatalf("Failed to build QUIC frames: %v", err)
	}

	qchframes, err := clienthellod.ReadAllFrames(bytes.NewReader(resultQUICPayload))
	if err != nil {
		t.Fatalf("Failed to read QUIC frames: %v", err)
	}

	reassembledCryptoData, err := clienthellod.ReassembleCRYPTOFrames(qchframes)
	if err != nil {
		t.Fatalf("Failed to reassemble crypto data: %v", err)
	}
	if !bytes.Equal(reassembledCryptoData, shortCryptoData) {
		t.Fatalf("Reassembled crypto data mismatch: got %x, want %x", reassembledCryptoData, shortCryptoData)
	}

	var cryptoCount int
	for _, frame := range qchframes {
		if frame.FrameType() == clienthellod.QUICFrame_CRYPTO {
			cryptoCount++
		}
	}
	if cryptoCount < 1 || cryptoCount > len(shortCryptoData) {
		t.Fatalf("CRYPTO frame count mismatch: got %d for %d bytes, want 1-%d",
			cryptoCount, len(shortCryptoData), len(shortCryptoData))
	}
}

var (
	testCryptoFrameBytes = []byte{
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b,
		0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23,
		0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b,
		0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33,
		0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b,
		0x3c, 0x3d, 0x3e, 0x3f,
	} // 64 bytes

	testQUICFrames = QUICFrames{
		// first 64 bytes: 01 + 63 bytes of padding
		&QUICFramePing{},
		&QUICFramePadding{Length: 63},
		// second 64 bytes: last 32 bytes of crypto frame + 29 bytes of padding
		&QUICFrameCrypto{
			Offset: 32,
			Length: 0,
		},
		&QUICFramePadding{Length: 29},
		// third 64 bytes: first 16 bytes of crypto frame + 45 bytes of padding
		&QUICFrameCrypto{
			Offset: 0,
			Length: 16,
		},
		&QUICFramePadding{Length: 45},
		// fourth 64 bytes: second 16 bytes of crypto frame + 45 bytes of padding
		&QUICFrameCrypto{
			Offset: 16,
			Length: 16,
		},
		&QUICFramePadding{Length: 45},
	}

	truthPayloadFromQUICFrames = []byte{
		0x01, // ping
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 63 bytes of padding
		0x06, 0x20, 0x20, // 3 bytes header
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, // 32 bytes of crypto frame
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, // 29 bytes of padding
		0x06, 0x00, 0x10, // 3 bytes header
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // 16 bytes of crypto frame
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, // 45 bytes of padding
		0x06, 0x10, 0x10, // 3 bytes header
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, // 16 bytes of crypto frame
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, // 45 bytes of padding
	}

	testQUICRandomFrames = QUICRandomFrames{
		MinPING:    2,
		MaxPING:    8,
		MinCRYPTO:  2,
		MaxCRYPTO:  8,
		MinPADDING: 4,
		MaxPADDING: 5,
		Length:     512,
	}
)
