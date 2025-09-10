package chat

import (
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

type State struct {
	ReadKey      []byte
	WriteKey     []byte
	ClientConnID []byte
	ServerConnID []byte
}

func QuicState(seed []byte) (*State, error) {
	rand := hkdf.New(sha256.New, seed, nil, nil)

	res := &State{
		ClientConnID: make([]byte, 8),
		ServerConnID: make([]byte, 8),
		ReadKey:      make([]byte, 32),
		WriteKey:     make([]byte, 32),
	}

	if _, err := rand.Read(res.ClientConnID); err != nil {
		return nil, err
	}
	if _, err := rand.Read(res.ServerConnID); err != nil {
		return nil, err
	}
	if _, err := rand.Read(res.ReadKey); err != nil {
		return nil, err
	}
	if _, err := rand.Read(res.WriteKey); err != nil {
		return nil, err
	}

	return res, nil
}
