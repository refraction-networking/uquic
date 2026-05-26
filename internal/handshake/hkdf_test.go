package handshake

import (
	"crypto"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/rand"
	tls "github.com/refraction-networking/utls" // [uQUIC]
	"testing"
)

// [uQUIC] TestHKDF was removed because it used go:linkname to access crypto/tls internals
// (crypto/tls.cipherSuitesTLS13 and crypto/tls.(*cipherSuiteTLS13).nextTrafficSecret).
// uQUIC replaces crypto/tls with utls, so crypto/tls is not in the dependency graph and
// the go:linkname approach fails at link time. See: 86fa4fd8 fix: remove tests that use go:linkname.

// tls13SuiteHash maps TLS 1.3 cipher suite IDs to their associated hash function.
var tls13SuiteHash = map[uint16]crypto.Hash{
	tls.TLS_AES_128_GCM_SHA256:       crypto.SHA256,
	tls.TLS_AES_256_GCM_SHA384:       crypto.SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256: crypto.SHA256,
}

// BenchmarkHKDFExpandLabelOurs benchmarks our hkdfExpandLabel implementation.
func BenchmarkHKDFExpandLabelOurs(b *testing.B) {
	for id, hash := range tls13SuiteHash {
		b.Run(tls.CipherSuiteName(id), func(b *testing.B) { benchmarkHKDFExpandLabel(b, hash) })
	}
}

func benchmarkHKDFExpandLabel(b *testing.B, hash crypto.Hash) {
	b.ReportAllocs()
	secret := make([]byte, 32)
	rand.Read(secret)

	for b.Loop() {
		hkdfExpandLabel(hash, secret, nil, "traffic upd", hash.Size())
	}
}
