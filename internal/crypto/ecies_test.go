package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello from lethe")
	ct, err := Encrypt(kp.EncPub, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := Decrypt(kp.EncPriv, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("expected %q got %q", plaintext, got)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	ct, err := Encrypt(kp1.EncPub, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = Decrypt(kp2.EncPriv, ct)
	if err != ErrDecryptFailed {
		t.Fatalf("expected ErrDecryptFailed, got %v", err)
	}
}

func TestDecryptTruncated(t *testing.T) {
	kp, _ := GenerateKeyPair()
	_, err := Decrypt(kp.EncPriv, []byte("tooshort"))
	if err != ErrDecryptFailed {
		t.Fatalf("expected ErrDecryptFailed, got %v", err)
	}
}

func TestEncryptDifferentCiphertexts(t *testing.T) {
	kp, _ := GenerateKeyPair()
	pt := []byte("same plaintext")

	ct1, _ := Encrypt(kp.EncPub, pt)
	ct2, _ := Encrypt(kp.EncPub, pt)

	// Each encryption uses a fresh ephemeral key + nonce — must differ
	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of the same plaintext should produce different ciphertexts")
	}

	// Both must decrypt correctly
	got1, err := Decrypt(kp.EncPriv, ct1)
	if err != nil || !bytes.Equal(got1, pt) {
		t.Fatal("ct1 decrypt failed")
	}
	got2, err := Decrypt(kp.EncPriv, ct2)
	if err != nil || !bytes.Equal(got2, pt) {
		t.Fatal("ct2 decrypt failed")
	}
}

func TestKeyPairSaveLoad(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir() + "/identity.json"
	if err := kp.Save(tmp); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadKeyPair(tmp)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.EncPubHex != kp.EncPubHex {
		t.Fatal("enc pub mismatch after load")
	}

	// Verify loaded key can decrypt message encrypted to original
	ct, _ := Encrypt(kp.EncPub, []byte("test"))
	pt, err := Decrypt(loaded.EncPriv, ct)
	if err != nil {
		t.Fatalf("decrypt with loaded key failed: %v", err)
	}
	if string(pt) != "test" {
		t.Fatal("plaintext mismatch")
	}
}
