package transport

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"

	"github.com/Operative-001/lethe/internal/protocol"
)

// TCPTransport implements Transport over raw TCP connections.
// Framing: each packet is preceded by a 2-byte big-endian length (always
// protocol.PacketSize, but we frame anyway for robustness).
type TCPTransport struct {
	listenAddr string
	listener   net.Listener
	incoming   chan protocol.Packet

	mu    sync.RWMutex
	peers map[string]net.Conn // addr → conn
}

// NewTCP creates a TCPTransport listening on listenAddr.
func NewTCP(listenAddr string) *TCPTransport {
	return &TCPTransport{
		listenAddr: listenAddr,
		incoming:   make(chan protocol.Packet, 512),
		peers:      make(map[string]net.Conn),
	}
}

func (t *TCPTransport) Start() error {
	ln, err := net.Listen("tcp", t.listenAddr)
	if err != nil {
		return err
	}
	t.listener = ln
	go t.acceptLoop()
	return nil
}

func (t *TCPTransport) Connect(addr string) error {
	t.mu.RLock()
	_, already := t.peers[addr]
	t.mu.RUnlock()
	if already {
		return nil
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	t.addPeer(addr, conn)
	return nil
}

func (t *TCPTransport) Broadcast(pkt protocol.Packet) {
	wire := pkt.Encode()

	t.mu.RLock()
	conns := make([]net.Conn, 0, len(t.peers))
	for _, c := range t.peers {
		conns = append(conns, c)
	}
	t.mu.RUnlock()

	for _, c := range conns {
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(protocol.PacketSize))
		c.Write(hdr[:])   //nolint:errcheck
		c.Write(wire[:])  //nolint:errcheck
	}
}

func (t *TCPTransport) Incoming() <-chan protocol.Packet {
	return t.incoming
}

func (t *TCPTransport) PeerCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.peers)
}

func (t *TCPTransport) Close() error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.mu.Lock()
	for _, c := range t.peers {
		c.Close()
	}
	t.mu.Unlock()
	return nil
}

func (t *TCPTransport) acceptLoop() {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			return
		}
		addr := conn.RemoteAddr().String()
		t.addPeer(addr, conn)
	}
}

func (t *TCPTransport) addPeer(addr string, conn net.Conn) {
	t.mu.Lock()
	t.peers[addr] = conn
	t.mu.Unlock()
	go t.readLoop(addr, conn)
}

func (t *TCPTransport) readLoop(addr string, conn net.Conn) {
	defer func() {
		conn.Close()
		t.mu.Lock()
		delete(t.peers, addr)
		t.mu.Unlock()
	}()

	for {
		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		sz := int(binary.BigEndian.Uint16(hdr[:]))
		if sz != protocol.PacketSize {
			log.Printf("transport: unexpected packet size %d from %s", sz, addr)
			return
		}
		buf := make([]byte, sz)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		pkt, err := protocol.Decode(buf)
		if err != nil {
			log.Printf("transport: decode error from %s: %v", addr, err)
			continue
		}
		select {
		case t.incoming <- pkt:
		default:
			// Drop if incoming buffer is full (backpressure)
		}
	}
}
