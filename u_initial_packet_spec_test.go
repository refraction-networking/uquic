package quic

import "testing"

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
