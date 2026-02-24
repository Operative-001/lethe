package directory

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
)

func newTestDir(t *testing.T) *Directory {
	t.Helper()
	tmp := t.TempDir()
	// bbolt needs the directory to exist, not to create subdirectories
	// We pass the temp dir itself as path (dir.go appends /directory.db)
	d, err := New(tmp)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		d.Close()
		os.RemoveAll(tmp)
	})
	return d
}

func newSignedEntry(t *testing.T, name string) (*Entry, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Fake X25519 pubkey (just 32 random bytes for test)
	encPrivBytes := make([]byte, 32)
	rand.Read(encPrivBytes)

	e := &Entry{
		Name:    name,
		EncPub:  hex.EncodeToString(encPrivBytes),
		SignPub: hex.EncodeToString(pub),
	}
	if err := e.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return e, priv
}

func TestAddAndLookup(t *testing.T) {
	d := newTestDir(t)
	e, _ := newSignedEntry(t, "alice")

	if err := d.Add(e); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got := d.Lookup("alice")
	if got == nil {
		t.Fatal("Lookup returned nil")
	}
	if got.EncPub != e.EncPub {
		t.Fatalf("EncPub mismatch: got %s want %s", got.EncPub, e.EncPub)
	}
}

func TestLookupMissing(t *testing.T) {
	d := newTestDir(t)
	if d.Lookup("nobody") != nil {
		t.Fatal("expected nil for missing entry")
	}
}

func TestAddInvalidSignature(t *testing.T) {
	d := newTestDir(t)
	e, _ := newSignedEntry(t, "mallory")
	// Tamper with the entry after signing
	e.Name = "tampered"
	if err := d.Add(e); err == nil {
		t.Fatal("expected signature verification failure")
	}
}

func TestNewerEntryReplaces(t *testing.T) {
	d := newTestDir(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signPubHex := hex.EncodeToString(pub)

	encBytes1 := make([]byte, 32)
	rand.Read(encBytes1)
	e1 := &Entry{Name: "bob", EncPub: hex.EncodeToString(encBytes1), SignPub: signPubHex}
	e1.Sign(priv)
	d.Add(e1)

	// Give it a moment so timestamp differs
	encBytes2 := make([]byte, 32)
	rand.Read(encBytes2)
	e2 := &Entry{Name: "bob", EncPub: hex.EncodeToString(encBytes2), SignPub: signPubHex}
	e2.Timestamp = e1.Timestamp + 1 // explicitly newer
	canonical, _ := e2.canonical()
	e2.Sig = ed25519.Sign(priv, canonical)

	d.Add(e2)

	got := d.Lookup("bob")
	if got.EncPub != e2.EncPub {
		t.Fatal("expected newer entry to replace older")
	}
}

func TestOlderEntryIgnored(t *testing.T) {
	d := newTestDir(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signPubHex := hex.EncodeToString(pub)

	encBytes1 := make([]byte, 32)
	rand.Read(encBytes1)
	e1 := &Entry{Name: "carol", EncPub: hex.EncodeToString(encBytes1), SignPub: signPubHex}
	e1.Timestamp = 2000
	canonical, _ := e1.canonical()
	e1.Sig = ed25519.Sign(priv, canonical)
	d.Add(e1)

	encBytes2 := make([]byte, 32)
	rand.Read(encBytes2)
	e2 := &Entry{Name: "carol", EncPub: hex.EncodeToString(encBytes2), SignPub: signPubHex}
	e2.Timestamp = 1000 // older
	canonical2, _ := e2.canonical()
	e2.Sig = ed25519.Sign(priv, canonical2)
	d.Add(e2)

	got := d.Lookup("carol")
	if got.EncPub != e1.EncPub {
		t.Fatal("older entry should not replace newer")
	}
}

func TestAll(t *testing.T) {
	d := newTestDir(t)
	for _, name := range []string{"alice", "bob", "carol"} {
		e, _ := newSignedEntry(t, name)
		d.Add(e)
	}
	all := d.All()
	if len(all) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(all))
	}
}
