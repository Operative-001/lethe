package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/curve25519"
)

// KeyPair holds both an X25519 encryption keypair and an Ed25519 signing keypair.
// The encryption public key is your network address.
type KeyPair struct {
	EncPriv [32]byte `json:"-"`
	EncPub  [32]byte `json:"-"`
	SignPriv ed25519.PrivateKey `json:"-"`
	SignPub  ed25519.PublicKey  `json:"-"`

	// Serialized forms for JSON
	EncPrivHex  string `json:"enc_priv"`
	EncPubHex   string `json:"enc_pub"`
	SignPrivHex string `json:"sign_priv"`
	SignPubHex  string `json:"sign_pub"`
}

func GenerateKeyPair() (*KeyPair, error) {
	// Generate X25519 keypair for encryption
	var encPriv [32]byte
	if _, err := io.ReadFull(rand.Reader, encPriv[:]); err != nil {
		return nil, err
	}
	// Clamp scalar
	encPriv[0] &= 248
	encPriv[31] &= 127
	encPriv[31] |= 64

	encPub, err := curve25519.X25519(encPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	// Generate Ed25519 keypair for signing
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	kp := &KeyPair{
		SignPriv: signPriv,
		SignPub:  signPub,
	}
	copy(kp.EncPriv[:], encPriv[:])
	copy(kp.EncPub[:], encPub)
	kp.syncHex()
	return kp, nil
}

func (kp *KeyPair) syncHex() {
	kp.EncPrivHex = hex.EncodeToString(kp.EncPriv[:])
	kp.EncPubHex = hex.EncodeToString(kp.EncPub[:])
	kp.SignPrivHex = hex.EncodeToString(kp.SignPriv)
	kp.SignPubHex = hex.EncodeToString(kp.SignPub)
}

func (kp *KeyPair) syncFromHex() error {
	b, err := hex.DecodeString(kp.EncPrivHex)
	if err != nil || len(b) != 32 {
		return errors.New("invalid enc_priv")
	}
	copy(kp.EncPriv[:], b)

	b, err = hex.DecodeString(kp.EncPubHex)
	if err != nil || len(b) != 32 {
		return errors.New("invalid enc_pub")
	}
	copy(kp.EncPub[:], b)

	b, err = hex.DecodeString(kp.SignPrivHex)
	if err != nil {
		return errors.New("invalid sign_priv")
	}
	kp.SignPriv = ed25519.PrivateKey(b)

	b, err = hex.DecodeString(kp.SignPubHex)
	if err != nil {
		return errors.New("invalid sign_pub")
	}
	kp.SignPub = ed25519.PublicKey(b)
	return nil
}

func (kp *KeyPair) PublicKeyHex() string {
	return kp.EncPubHex
}

func (kp *KeyPair) Sign(data []byte) []byte {
	return ed25519.Sign(kp.SignPriv, data)
}

func (kp *KeyPair) Save(path string) error {
	kp.syncHex()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(kp)
}

func LoadKeyPair(path string) (*KeyPair, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	kp := &KeyPair{}
	if err := json.NewDecoder(f).Decode(kp); err != nil {
		return nil, err
	}
	return kp, kp.syncFromHex()
}

// PubKeyFromHex parses a 32-byte hex-encoded X25519 public key.
func PubKeyFromHex(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, errors.New("public key must be 32 bytes")
	}
	copy(out[:], b)
	return out, nil
}
