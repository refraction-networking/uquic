package quic

import (
	"testing"

	tls "github.com/refraction-networking/utls"
)

// canonicalQTPs is a representative Chrome-like transport parameter list, in a
// fixed (sorted) order, as a spec would declare it.
func canonicalQTPs() tls.TransportParameters {
	return tls.TransportParameters{
		tls.MaxIdleTimeout(30000),               // 0x01
		tls.MaxUDPPayloadSize(1472),             // 0x03
		tls.InitialMaxData(0x300000),            // 0x04
		tls.InitialMaxStreamDataBidiLocal(1e6),  // 0x05
		tls.InitialMaxStreamDataBidiRemote(1e6), // 0x06
		tls.InitialMaxStreamDataUni(1e6),        // 0x07
		tls.InitialMaxStreamsBidi(100),          // 0x08
		tls.InitialMaxStreamsUni(100),           // 0x09
		tls.ActiveConnectionIDLimit(2),          // 0x0e
	}
}

func qtpIDs(tps tls.TransportParameters) []uint64 {
	ids := make([]uint64, len(tps))
	for i, tp := range tps {
		ids[i] = tp.ID()
	}
	return ids
}

func multiset(ids []uint64) map[uint64]int {
	m := make(map[uint64]int, len(ids))
	for _, id := range ids {
		m[id]++
	}
	return m
}

func equalMultiset(a, b map[uint64]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestShuffleQUICTransportParametersPermutation verifies that shuffling always
// yields a valid permutation (same multiset of parameter IDs, no loss/dup) —
// this is the slice uTLS serializes directly onto the wire.
func TestShuffleQUICTransportParametersPermutation(t *testing.T) {
	wantMS := multiset(qtpIDs(canonicalQTPs()))

	for i := 0; i < 200; i++ {
		ext := &tls.QUICTransportParametersExtension{TransportParameters: canonicalQTPs()}
		ShuffleQUICTransportParameters(ext)
		got := qtpIDs(ext.TransportParameters)
		if len(got) != len(wantMS) {
			t.Fatalf("shuffle changed length: got %d, want %d", len(got), len(wantMS))
		}
		if !equalMultiset(multiset(got), wantMS) {
			t.Fatalf("shuffle is not a permutation of the input: got %v", got)
		}
	}
}

// TestShuffleQUICTransportParametersVaries verifies the wire order actually
// varies across connections, i.e. the order is not effectively fixed.
func TestShuffleQUICTransportParametersVaries(t *testing.T) {
	baseline := qtpIDs(canonicalQTPs())

	seen := make(map[string]struct{})
	differedFromCanonical := false
	for i := 0; i < 100; i++ {
		ext := &tls.QUICTransportParametersExtension{TransportParameters: canonicalQTPs()}
		ShuffleQUICTransportParameters(ext)
		ids := qtpIDs(ext.TransportParameters)

		key := ""
		differs := false
		for j, id := range ids {
			key += string(rune(id)) + ","
			if id != baseline[j] {
				differs = true
			}
		}
		if differs {
			differedFromCanonical = true
		}
		seen[key] = struct{}{}
	}
	if !differedFromCanonical {
		t.Fatal("shuffle never produced an order different from the canonical order")
	}
	// With 9 params over 100 trials, we expect many distinct permutations.
	if len(seen) < 10 {
		t.Fatalf("shuffle produced too few distinct orders (%d); randomization looks weak", len(seen))
	}
}
