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

// Verifies that Build does not panic when called with empty cryptoData.
// This reproduces a scenario where a QUIC probe packet retransmits with
// no actual crypto payload, causing uint64 underflow in the CRYPTO
// frame length calculation.
func TestQUICRandomFramesEmptyCryptoData(t *testing.T) {
	qrf := &QUICRandomFrames{
		MinPING:    0,
		MaxPING:    3,
		MinCRYPTO:  2, // Must be >=2 to enter the splitting loop
		MaxCRYPTO:  4,
		MinPADDING: 1,
		MaxPADDING: 3,
		Length:     100,
	}

	payload, err := qrf.Build([]byte{})
	if err != nil {
		t.Fatalf("Build with empty cryptoData returned error: %v", err)
	}
	if payload == nil {
		t.Fatal("Build with empty cryptoData returned nil payload")
	}
}

// Verifies Build handles the edge case where cryptoData is too small
// to split across multiple CRYPTO frames without underflow.
func TestQUICRandomFramesSingleByteCryptoData(t *testing.T) {
	qrf := &QUICRandomFrames{
		MinPING:    0,
		MaxPING:    2,
		MinCRYPTO:  3, // Requesting 3+ splits of 1 byte
		MaxCRYPTO:  5,
		MinPADDING: 1,
		MaxPADDING: 2,
		Length:     50,
	}

	payload, err := qrf.Build([]byte{0x42})
	if err != nil {
		t.Fatalf("Build with single-byte cryptoData returned error: %v", err)
	}
	if payload == nil {
		t.Fatal("Build with single-byte cryptoData returned nil payload")
	}
}

func TestQUICFramesEmptyCryptoData(t *testing.T) {
	frames := QUICFrames{
		QUICFrameCrypto{Offset: 0, Length: 0},
	}

	payload, err := frames.Build([]byte{})
	if err != nil {
		t.Fatalf("Build with empty cryptoData returned error: %v", err)
	}
	if payload == nil {
		t.Fatal("Build returned nil payload")
	}
}

func TestQUICFramesOffsetExceedsCryptoData(t *testing.T) {
	frames := QUICFrames{
		QUICFrameCrypto{Offset: 100, Length: 0}, // offset far beyond data
	}

	payload, err := frames.Build([]byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("Build with excessive offset returned error: %v", err)
	}
	if payload == nil {
		t.Fatal("Build returned nil payload")
	}
}
