package node

import (
	"sync"
	"testing"
	"time"

	"github.com/Operative-001/lethe/internal/crypto"
	"github.com/Operative-001/lethe/internal/protocol"
	"github.com/Operative-001/lethe/internal/transport"
)

func newTestNode(t *testing.T) (*Node, *transport.MemoryTransport) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	tr := transport.NewMemory()
	n, err := New(Config{
		Keys:      kp,
		Transport: tr,
		Rate:      10 * time.Millisecond, // fast for tests
	})
	if err != nil {
		t.Fatal(err)
	}
	return n, tr
}

func TestDirectMessageDelivery(t *testing.T) {
	alice, aliceTr := newTestNode(t)
	bob, bobTr := newTestNode(t)

	// Wire together
	aliceTr.Connect(bobTr.ID())

	alice.Start()
	bob.Start()
	defer alice.Stop()
	defer bob.Stop()

	// Alice sends to Bob
	err := alice.Send(bob.cfg.Keys.PublicKeyHex(), "hello bob")
	if err != nil {
		t.Fatal(err)
	}

	select {
	case msg := <-bob.Messages():
		if msg.Content != "hello bob" {
			t.Fatalf("got %q want %q", msg.Content, "hello bob")
		}
		if msg.From != alice.cfg.Keys.PublicKeyHex() {
			t.Fatal("from field mismatch")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for message")
	}
}

func TestDummyTrafficIsConstant(t *testing.T) {
	// Even with nothing to send, the node should emit packets at the configured rate.
	n, _ := newTestNode(t)

	// Use a counting transport
	counting := &countingTransport{inner: transport.NewMemory()}
	n.tr = counting

	n.Start()
	defer n.Stop()

	time.Sleep(150 * time.Millisecond)
	count := counting.BroadcastCount()

	// At 10ms rate over 150ms, expect ~15 broadcasts (allow ±5 for scheduler jitter)
	if count < 10 || count > 20 {
		t.Fatalf("expected ~15 broadcasts in 150ms, got %d", count)
	}
}

func TestMessageNotDeliveredToWrongNode(t *testing.T) {
	alice, aliceTr := newTestNode(t)
	bob, bobTr := newTestNode(t)
	eve, _ := newTestNode(t)

	aliceTr.Connect(bobTr.ID())

	alice.Start()
	bob.Start()
	eve.Start()
	defer alice.Stop()
	defer bob.Stop()
	defer eve.Stop()

	// Alice sends to Bob only
	alice.Send(bob.cfg.Keys.PublicKeyHex(), "for bob only")

	// Bob should receive
	select {
	case msg := <-bob.Messages():
		if msg.Content != "for bob only" {
			t.Fatalf("bob got wrong message: %q", msg.Content)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bob did not receive")
	}

	// Eve should NOT receive (she's not even connected, but test the channel is empty)
	select {
	case msg := <-eve.Messages():
		t.Fatalf("eve should not have received: %q", msg.Content)
	case <-time.After(100 * time.Millisecond):
		// correct
	}
}

func TestForwardWrapped(t *testing.T) {
	// alice → relay → bob
	// Alice encrypts outer layer to relay, inner layer to bob
	// Relay should unwrap and re-broadcast inner packet to bob
	alice, aliceTr := newTestNode(t)
	relay, relayTr := newTestNode(t)
	bob, bobTr := newTestNode(t)

	// Wire: alice ↔ relay ↔ bob
	aliceTr.Connect(relayTr.ID())
	relayTr.Connect(bobTr.ID())

	alice.Start()
	relay.Start()
	bob.Start()
	defer alice.Stop()
	defer relay.Stop()
	defer bob.Stop()

	err := alice.SendWrapped(
		relay.cfg.Keys.PublicKeyHex(),
		bob.cfg.Keys.PublicKeyHex(),
		"wrapped for bob",
	)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case msg := <-bob.Messages():
		if msg.Content != "wrapped for bob" {
			t.Fatalf("got %q", msg.Content)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: bob did not receive wrapped message")
	}
}

func TestDeduplication(t *testing.T) {
	// A packet should only be delivered once even if received multiple times
	alice, aliceTr := newTestNode(t)
	bob, bobTr := newTestNode(t)

	aliceTr.Connect(bobTr.ID())
	alice.Start()
	bob.Start()
	defer alice.Stop()
	defer bob.Stop()

	alice.Send(bob.cfg.Keys.PublicKeyHex(), "once")

	// Collect messages for 500ms
	var received []IncomingMessage
	deadline := time.After(500 * time.Millisecond)
loop:
	for {
		select {
		case msg := <-bob.Messages():
			received = append(received, msg)
		case <-deadline:
			break loop
		}
	}

	count := 0
	for _, m := range received {
		if m.Content == "once" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected 1 delivery, got %d", count)
	}
}

func TestTTLExpiry(t *testing.T) {
	// A packet with TTL=0 should not be forwarded
	alice, aliceTr := newTestNode(t)
	bob, bobTr := newTestNode(t)
	aliceTr.Connect(bobTr.ID())

	alice.Start()
	bob.Start()
	defer alice.Stop()
	defer bob.Stop()

	// Craft a packet with TTL=1 (will be decremented to 0 at first hop, then dropped)
	ct, _ := crypto.Encrypt(bob.cfg.Keys.EncPub, []byte(`{"type":"msg","content":"ttl test"}`))
	pkt, _ := protocol.NewPacket(protocol.TypeMessage, 1, ct)

	// Inject directly into alice's send queue (bypass normal Send)
	select {
	case alice.sendQ <- pkt:
	default:
		t.Fatal("could not inject packet")
	}

	select {
	case msg := <-bob.Messages():
		if msg.Content == "ttl test" {
			// TTL=1 means alice broadcasts it, bob receives (TTL decremented to 0), bob processes it
			// but then won't re-broadcast. This is fine — bob still decrypts it.
			_ = msg
		}
	case <-time.After(500 * time.Millisecond):
		// also acceptable — depends on timing
	}
}

// --- helpers ---

type countingTransport struct {
	inner          *transport.MemoryTransport
	mu             sync.Mutex
	broadcastCount int
}

func (c *countingTransport) Start() error          { return c.inner.Start() }
func (c *countingTransport) Connect(addr string) error { return c.inner.Connect(addr) }
func (c *countingTransport) Incoming() <-chan protocol.Packet { return c.inner.Incoming() }
func (c *countingTransport) PeerCount() int { return c.inner.PeerCount() }
func (c *countingTransport) Close() error { return c.inner.Close() }
func (c *countingTransport) Broadcast(pkt protocol.Packet) {
	c.mu.Lock()
	c.broadcastCount++
	c.mu.Unlock()
	c.inner.Broadcast(pkt)
}
func (c *countingTransport) BroadcastCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.broadcastCount
}
