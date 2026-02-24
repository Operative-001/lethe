package transport

import (
	"fmt"
	"sync"

	"github.com/Operative-001/lethe/internal/protocol"
)

// MemoryTransport is an in-process transport for tests.
// Call Connect(otherTransport.ID()) to wire two transports together.
// A global registry maps string IDs to MemoryTransport instances.
type MemoryTransport struct {
	id       string
	incoming chan protocol.Packet

	mu    sync.RWMutex
	peers map[string]*MemoryTransport
}

var (
	registryMu sync.Mutex
	registry   = map[string]*MemoryTransport{}
	nextID     int
)

// NewMemory creates a MemoryTransport with a unique ID.
func NewMemory() *MemoryTransport {
	registryMu.Lock()
	nextID++
	id := fmt.Sprintf("mem-%d", nextID)
	t := &MemoryTransport{
		id:       id,
		incoming: make(chan protocol.Packet, 1024),
		peers:    make(map[string]*MemoryTransport),
	}
	registry[id] = t
	registryMu.Unlock()
	return t
}

func (t *MemoryTransport) ID() string { return t.id }

func (t *MemoryTransport) Start() error { return nil }

func (t *MemoryTransport) Connect(addr string) error {
	registryMu.Lock()
	other, ok := registry[addr]
	registryMu.Unlock()
	if !ok {
		return fmt.Errorf("memory transport: no peer with id %q", addr)
	}

	t.mu.Lock()
	t.peers[addr] = other
	t.mu.Unlock()

	// Also wire the reverse so the other side can send back
	other.mu.Lock()
	other.peers[t.id] = t
	other.mu.Unlock()

	return nil
}

func (t *MemoryTransport) Broadcast(pkt protocol.Packet) {
	t.mu.RLock()
	peers := make([]*MemoryTransport, 0, len(t.peers))
	for _, p := range t.peers {
		peers = append(peers, p)
	}
	t.mu.RUnlock()

	for _, p := range peers {
		select {
		case p.incoming <- pkt:
		default:
		}
	}
}

func (t *MemoryTransport) Incoming() <-chan protocol.Packet {
	return t.incoming
}

func (t *MemoryTransport) PeerCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.peers)
}

func (t *MemoryTransport) Close() error {
	registryMu.Lock()
	delete(registry, t.id)
	registryMu.Unlock()
	return nil
}
