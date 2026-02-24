package seen

import (
	"crypto/rand"
	"io"
	"testing"
	"time"
)

func randomNonce() [32]byte {
	var n [32]byte
	io.ReadFull(rand.Reader, n[:])
	return n
}

func TestAddAndHas(t *testing.T) {
	c := New(10 * time.Second)
	n := randomNonce()

	if c.Has(n) {
		t.Fatal("fresh cache should not have nonce")
	}
	if !c.Add(n) {
		t.Fatal("first Add should return true (new)")
	}
	if !c.Has(n) {
		t.Fatal("should have nonce after Add")
	}
	if c.Add(n) {
		t.Fatal("second Add should return false (duplicate)")
	}
}

func TestExpiry(t *testing.T) {
	c := New(50 * time.Millisecond)
	n := randomNonce()
	c.Add(n)

	if !c.Has(n) {
		t.Fatal("should have nonce immediately after Add")
	}

	time.Sleep(100 * time.Millisecond)
	if c.Has(n) {
		t.Fatal("nonce should have expired")
	}
}

func TestMultipleNonces(t *testing.T) {
	c := New(10 * time.Second)
	nonces := make([][32]byte, 100)
	for i := range nonces {
		nonces[i] = randomNonce()
		c.Add(nonces[i])
	}
	if c.Len() < 100 {
		t.Fatalf("expected at least 100 entries, got %d", c.Len())
	}
	for _, n := range nonces {
		if !c.Has(n) {
			t.Fatal("missing nonce")
		}
	}
}

func TestDifferentNoncesIndependent(t *testing.T) {
	c := New(10 * time.Second)
	n1 := randomNonce()
	n2 := randomNonce()
	c.Add(n1)

	if !c.Has(n1) {
		t.Fatal("n1 should be present")
	}
	if c.Has(n2) {
		t.Fatal("n2 should not be present")
	}
}
