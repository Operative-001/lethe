// Package crypto provides ECIES-style encryption using X25519 + ChaCha20-Poly1305.
//
// Every message is encrypted to a recipient's X25519 public key. Decryption
// succeeds only for the holder of the matching private key. This property is
// used by the broadcast engine: every node attempts to decrypt every packet;
// a successful authentication tag means the packet is addressed to this node.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const hkdfInfo = "lethe-v1"

// Encrypt encrypts plaintext to recipientPub using ECIES:
//   - Ephemeral X25519 keypair generated per message
//   - Shared secret via ECDH
//   - Key derived with HKDF-SHA256
//   - Authenticated encryption with ChaCha20-Poly1305
//
// Output format: ephPub(32) || nonce(12) || ciphertext+tag
func Encrypt(recipientPub [32]byte, plaintext []byte) ([]byte, error) {
	// Ephemeral keypair
	ephPriv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, ephPriv); err != nil {
		return nil, err
	}
	ephPriv[0] &= 248
	ephPriv[31] &= 127
	ephPriv[31] |= 64

	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	shared, err := curve25519.X25519(ephPriv, recipientPub[:])
	if err != nil {
		return nil, err
	}

	key, err := deriveKey(shared, ephPub)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ct := aead.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 0, 32+len(nonce)+len(ct))
	out = append(out, ephPub...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Decrypt attempts to decrypt data using privKey.
// Returns ErrDecryptFailed if the authentication tag does not match
// (i.e. the packet is not addressed to this key — expected and normal).
func Decrypt(privKey [32]byte, data []byte) ([]byte, error) {
	if len(data) < 32+12+16 {
		return nil, ErrDecryptFailed
	}

	ephPub := data[:32]
	nonce := data[32:44]
	ct := data[44:]

	shared, err := curve25519.X25519(privKey[:], ephPub)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	key, err := deriveKey(shared, ephPub)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return pt, nil
}

// ErrDecryptFailed is returned when decryption fails (wrong key or corrupt data).
// Callers should treat this as "not for me" — it is not an error condition.
var ErrDecryptFailed = errors.New("decrypt: authentication failed")

func deriveKey(shared, ephPub []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, shared, ephPub[:8], []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}
