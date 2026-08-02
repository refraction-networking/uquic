package quic

import (
	"bytes"
	"testing"
)

// stubTokenStore is a user-supplied TokenStore used to verify UpdateConfig does
// not clobber a caller's store when the spec specifies no token settings.
type stubTokenStore struct{}

func (stubTokenStore) Pop(string) *ClientToken  { return nil }
func (stubTokenStore) Put(string, *ClientToken) {}

// TestUpdateConfigClientTokenLength verifies that ClientTokenLength installs a
// TokenStore that yields tokens of the requested length — the link that was
// missing (UpdateConfig was never called on dial, so the token was always empty).
func TestUpdateConfigClientTokenLength(t *testing.T) {
	spec := &QUICSpec{InitialPacketSpec: InitialPacketSpec{ClientTokenLength: 70}}
	conf := &Config{}
	spec.UpdateConfig(conf)

	if conf.TokenStore == nil {
		t.Fatal("expected TokenStore to be set for ClientTokenLength > 0")
	}
	tok := conf.TokenStore.Pop("any-key")
	if tok == nil {
		t.Fatal("expected a token from the spec-derived TokenStore")
	}
	if len(tok.data) != 70 {
		t.Fatalf("token length = %d, want 70", len(tok.data))
	}
}

// TestUpdateConfigClientTokenPrefix verifies that ClientTokenPrefix pins the leading
// token bytes (Chrome's tokens always start 0x00) while the remainder stays random per
// connection, and that the token is still ClientTokenLength bytes long.
func TestUpdateConfigClientTokenPrefix(t *testing.T) {
	spec := &QUICSpec{InitialPacketSpec: InitialPacketSpec{
		ClientTokenPrefix: []byte{0x00},
		ClientTokenLength: 70,
	}}
	conf := &Config{}
	spec.UpdateConfig(conf)

	first := conf.TokenStore.Pop("any-key")
	if first == nil {
		t.Fatal("expected a token from the spec-derived TokenStore")
	}
	if len(first.data) != 70 {
		t.Fatalf("token length = %d, want 70", len(first.data))
	}
	if first.data[0] != 0x00 {
		t.Fatalf("token[0] = %#x, want 0x00", first.data[0])
	}

	// Each connection must get a fresh token: a constant token is its own tell.
	second := conf.TokenStore.Pop("any-key")
	if second.data[0] != 0x00 {
		t.Fatalf("second token[0] = %#x, want 0x00", second.data[0])
	}
	if bytes.Equal(first.data[1:], second.data[1:]) {
		t.Fatal("token remainder is not regenerated per Pop")
	}
}

// TestUpdateConfigClientTokenPrefixOnly verifies that a prefix alone (no
// ClientTokenLength) installs the store and sends those exact bytes verbatim.
func TestUpdateConfigClientTokenPrefixOnly(t *testing.T) {
	want := []byte{0x00, 0xc3, 0xec, 0x05}
	spec := &QUICSpec{InitialPacketSpec: InitialPacketSpec{ClientTokenPrefix: want}}
	conf := &Config{}
	spec.UpdateConfig(conf)

	if conf.TokenStore == nil {
		t.Fatal("expected TokenStore to be set for a non-empty ClientTokenPrefix")
	}
	tok := conf.TokenStore.Pop("any-key")
	if tok == nil {
		t.Fatal("expected a token from the spec-derived TokenStore")
	}
	if !bytes.Equal(tok.data, want) {
		t.Fatalf("token = %#x, want %#x", tok.data, want)
	}
}

// TestNewClientToken verifies a TokenStore outside this package can build a token
// with chosen bytes, and that it does not alias the caller's buffer.
func TestNewClientToken(t *testing.T) {
	buf := []byte{0x00, 0x01, 0x02}
	tok := NewClientToken(buf)
	buf[0] = 0xff

	if !bytes.Equal(tok.data, []byte{0x00, 0x01, 0x02}) {
		t.Fatalf("token data = %#x, want 000102 (caller's buffer must not alias)", tok.data)
	}
}

// TestUpdateConfigDoesNotClobberUserTokenStore verifies that when the spec sets
// neither TokenStore nor ClientTokenLength, a user-provided conf.TokenStore is
// left intact rather than overwritten with nil.
func TestUpdateConfigDoesNotClobberUserTokenStore(t *testing.T) {
	user := stubTokenStore{}
	conf := &Config{TokenStore: user}
	spec := &QUICSpec{InitialPacketSpec: InitialPacketSpec{}} // no token settings
	spec.UpdateConfig(conf)

	if conf.TokenStore == nil {
		t.Fatal("UpdateConfig clobbered the user-supplied TokenStore with nil")
	}
	if _, ok := conf.TokenStore.(stubTokenStore); !ok {
		t.Fatalf("user TokenStore was replaced: got %T", conf.TokenStore)
	}
}

// TestUpdateConfigExplicitTokenStoreWins verifies an explicit InitialPacketSpec
// TokenStore takes priority over ClientTokenLength.
func TestUpdateConfigExplicitTokenStoreWins(t *testing.T) {
	user := stubTokenStore{}
	spec := &QUICSpec{InitialPacketSpec: InitialPacketSpec{
		TokenStore:        user,
		ClientTokenLength: 70,
	}}
	conf := &Config{}
	spec.UpdateConfig(conf)

	if _, ok := conf.TokenStore.(stubTokenStore); !ok {
		t.Fatalf("explicit TokenStore did not win: got %T", conf.TokenStore)
	}
}
