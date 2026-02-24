// Package transport defines the peer communication interface and provides
// implementations for production (TCP) and testing (in-memory).
package transport

import (
	"github.com/Operative-001/lethe/internal/protocol"
)

// Transport abstracts peer-to-peer packet I/O.
// The node uses this interface exclusively so that tests can inject an
// in-memory transport without needing real network sockets.
type Transport interface {
	// Start begins listening for incoming peer connections.
	Start() error

	// Connect dials a peer by address. Idempotent if already connected.
	Connect(addr string) error

	// Broadcast sends pkt to all currently connected peers.
	Broadcast(pkt protocol.Packet)

	// Incoming returns a channel of packets received from any peer.
	Incoming() <-chan protocol.Packet

	// PeerCount returns the number of currently connected peers.
	PeerCount() int

	// Close shuts down the transport and all peer connections.
	Close() error
}
