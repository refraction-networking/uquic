package kyber

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type Host struct {
	privateKey [32]byte
	publicKey  [32]byte
	derivedKey []byte
}

// NewHost initializes a Host with an X25519 private key
func NewHost() *Host {
	host := &Host{}
	_, err := rand.Read(host.privateKey[:])
	if err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&host.publicKey, &host.privateKey)
	return host
}

// ComputeSharedKey computes the shared secret using the other party's public key
func (h *Host) ComputeSharedKey(peerPublicKey [32]byte) []byte {
	sharedKey := [32]byte{}
	curve25519.ScalarMult(&sharedKey, &h.privateKey, &peerPublicKey)

	hkdf := hkdf.New(sha256.New, sharedKey[:], nil, []byte("handshake data"))
	derivedKey := make([]byte, 32)
	if _, err := hkdf.Read(derivedKey); err != nil {
		panic(err)
	}
	h.derivedKey = derivedKey
	return derivedKey
}

// GetPublicKey returns the public key of the Host
func (h *Host) GetPublicKey() [32]byte {
	return h.publicKey
}

type Client struct {
	*Host
}

// NewClient initializes a Client
func NewClient() *Client {
	return &Client{NewHost()}
}

// GenKyber generates a Kyber-style payload
func (c *Client) GenKyber(data []byte) []byte {
	if len(data) > 1121 {
		panic("data length exceeds maximum")
	}
	parrot := append([]byte{}, c.publicKey[:]...)
	paddedData := append(data, make([]byte, 1121-len(data))...)
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, uint16(1121-len(data)))
	paddedData = append(paddedData, lengthBytes...)

	nonce := make([]byte, 12)
	_, err := rand.Read(nonce)
	if err != nil {
		panic(err)
	}
	aesBlock, err := aes.NewCipher(c.derivedKey)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		panic(err)
	}

	ciphertext := gcm.Seal(nil, nonce, paddedData, nil)
	tag := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]
	encodedCiphertext := Encode(encodeBytesToBase3329(ciphertext), 12)

	randPad := make([]byte, 4)
	_, err = rand.Read(randPad)
	if err != nil {
		panic(err)
	}

	parrot = append(parrot, encodedCiphertext...)
	parrot = append(parrot, nonce...)
	parrot = append(parrot, tag...)
	parrot = append(parrot, randPad...)
	// The tag is already included in the ciphertext returned by gcm.Seal
	return parrot
}

type Server struct {
	*Host
}

// NewServer initializes a Server
func NewServer() *Server {
	return &Server{NewHost()}
}

// DecodeKyber decodes the Kyber-style payload and extracts the original data
func (s *Server) DecodeKyber(parrot []byte) []byte {
	var clientPublicKey [32]byte
	copy(clientPublicKey[:], parrot[:32])

	s.ComputeSharedKey(clientPublicKey)

	encodedCiphertext := parrot[32:1184]
	nonce := parrot[1184:1196]
	tag := parrot[1196:1212]

	ciphertext := decodeBase3329ToBytes(Decode(encodedCiphertext, 12))
	aesBlock, err := aes.NewCipher(s.derivedKey)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCMWithNonceSize(aesBlock, 12)
	if err != nil {
		panic(err)
	}

	gcmCiphertext := append(ciphertext, tag...)
	decryptedData, err := gcm.Open(nil, nonce, gcmCiphertext, nil)
	if err != nil {
		panic(err)
	}

	length := int(binary.BigEndian.Uint16(decryptedData[1121:1123]))
	return decryptedData[:1121-length]
}

// Helper functions for encoding and decoding base 3329
func encodeBytesToBase3329(byteData []byte) []int {
	base := big.NewInt(3329)
	encoded := []int{}
	for len(encoded) != 768 {
		val := new(big.Int).Exp(big.NewInt(3329), big.NewInt(768), nil)
		val = val.Add(val, big.NewInt(1))
		check := new(big.Int).Exp(big.NewInt(3329), big.NewInt(768), nil)
		for val.Cmp(check) > 0 {
			randPad := make([]byte, 1)
			_, err := rand.Read(randPad)
			if err != nil {
				panic(err)
			}
			randPad[0] &= 0x7
			randPad = append(randPad, byteData...)
			val = new(big.Int).SetBytes(randPad)
		}
		encoded = []int{}
		for val.Cmp(big.NewInt(0)) > 0 {
			mod := big.NewInt(0)
			val.DivMod(val, base, mod)
			encoded = append(encoded, int(mod.Int64()))
		}
	}
	return encoded
}

func decodeBase3329ToBytes(base3329 []int) []byte {
	base := big.NewInt(3329)
	n := big.NewInt(0)
	for i := len(base3329) - 1; i >= 0; i-- {
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(base3329[i])))
	}
	for i := n.BitLen(); i > 8984; i-- {
		n = n.SetBit(n, i-1, 0)
	}
	return n.FillBytes(make([]byte, 1123))
}

// BitsToWords converts a bit slice to a slice of words of width `w`
func BitsToWords(bs []int, w int) []int {
	if len(bs)%w != 0 {
		panic("length of bs is not a multiple of w")
	}

	words := []int{}
	for i := 0; i < len(bs); i += w {
		word := 0
		for j := 0; j < w; j++ {
			word += bs[i+j] * (1 << j)
		}
		words = append(words, word)
	}
	return words
}

// WordsToBits converts a slice of words to a bit slice of width `w`
func WordsToBits(bs []int, w int) []int {
	bits := []int{}
	for _, b := range bs {
		wordBits := make([]int, w)
		for i := 0; i < w; i++ {
			wordBits[i] = (b >> i) & 1
		}
		bits = append(bits, wordBits...)
	}
	return bits
}

// Encode converts a slice of words to bytes using bit width `w`
func Encode(a []int, w int) []byte {
	bits := WordsToBits(a, w)
	words := BitsToWords(bits, 8)

	encoded := make([]byte, len(words))
	for i, word := range words {
		encoded[i] = byte(word)
	}
	return encoded
}

// Decode converts a byte slice back to words using bit width `w`
func Decode(a []byte, w int) []int {
	bits := []int{}
	for _, b := range a {
		for i := 0; i < 8; i++ {
			bits = append(bits, int((b>>i)&1))
		}
	}
	return BitsToWords(bits, w)
}

func main() {
	for i := 0; i < 10000; i++ {
		client := NewClient()
		server := NewServer()

		clientData := []byte("hello world")
		client.ComputeSharedKey(server.GetPublicKey())
		x25519kyber768Parrot := client.GenKyber(clientData)

		serverData := server.DecodeKyber(x25519kyber768Parrot)
		if string(clientData) != string(serverData) {
			panic("Data mismatch")
		}
		fmt.Println("Successful round", i+1)
	}
}
