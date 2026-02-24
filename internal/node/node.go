// Package node implements the Lethe protocol engine.
//
// Design:
//   - One goroutine runs the constant-rate broadcast scheduler.
//   - One goroutine processes incoming packets from the transport.
//   - The scheduler emits one packet per tick: a real packet if one is queued,
//     otherwise a dummy. This maintains constant outbound traffic at all times.
//   - Every received packet is (a) attempted for decryption with the local key,
//     (b) queued for re-broadcast regardless of whether decryption succeeded.
//     The re-broadcast goes through the scheduler, so it is time-shifted and
//     indistinguishable from locally-originated traffic.
package node

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Operative-001/lethe/internal/crypto"
	"github.com/Operative-001/lethe/internal/directory"
	"github.com/Operative-001/lethe/internal/protocol"
	"github.com/Operative-001/lethe/internal/seen"
	"github.com/Operative-001/lethe/internal/transport"
)

const (
	defaultRate      = 100 * time.Millisecond // 10 pkt/s
	sendQueueDepth   = 256
)

// Config configures a Node.
type Config struct {
	Keys        *crypto.KeyPair
	Transport   transport.Transport
	Directory   *directory.Directory
	Rate        time.Duration   // broadcast interval; defaults to defaultRate
	Bootstrap   []string        // peer addresses to connect on start
	Listen      string          // TCP listen address (ignored when Transport is provided)
	ProxyAddr   string          // SOCKS5 proxy bind address
	ExposePort  int             // local TCP port to expose as a hidden service (0 = not hosting)
}

// IncomingMessage is delivered to callers via the Messages() channel.
type IncomingMessage struct {
	From    string // sender's enc_pub hex, if provided
	Content string
}

// Node is the Lethe protocol engine.
type Node struct {
	cfg      Config
	tr       transport.Transport
	seen     *seen.Cache
	dir      *directory.Directory
	sendQ    chan protocol.Packet
	messages chan IncomingMessage
	sessions *SessionManager

	stopOnce sync.Once
	stopCh   chan struct{}
}

// New creates a Node. If cfg.Transport is nil, a TCP transport is created
// using cfg.Listen.
func New(cfg Config) (*Node, error) {
	if cfg.Rate == 0 {
		cfg.Rate = defaultRate
	}
	tr := cfg.Transport
	if tr == nil {
		if cfg.Listen == "" {
			cfg.Listen = "0.0.0.0:4242"
		}
		tr = transport.NewTCP(cfg.Listen)
	}
	n := &Node{
		cfg:      cfg,
		tr:       tr,
		seen:     seen.New(60 * time.Second),
		dir:      cfg.Directory,
		sendQ:    make(chan protocol.Packet, sendQueueDepth),
		messages: make(chan IncomingMessage, 64),
		stopCh:   make(chan struct{}),
	}
	n.sessions = newSessionManager(n, cfg.ExposePort)
	return n, nil
}

// Start begins the node: starts transport, connects to bootstrap peers,
// and launches the broadcast and receive goroutines.
func (n *Node) Start() error {
	if err := n.tr.Start(); err != nil {
		return fmt.Errorf("node: transport start: %w", err)
	}
	for _, addr := range n.cfg.Bootstrap {
		if err := n.tr.Connect(addr); err != nil {
			log.Printf("node: bootstrap %s: %v", addr, err)
		}
	}
	go n.broadcastLoop()
	go n.receiveLoop()
	return nil
}

// Stop shuts down the node.
func (n *Node) Stop() {
	n.stopOnce.Do(func() {
		close(n.stopCh)
		n.tr.Close() //nolint:errcheck
	})
}

// Messages returns a channel of messages delivered to this node.
func (n *Node) Messages() <-chan IncomingMessage {
	return n.messages
}

// Send encrypts and queues a message to the given recipient public key.
// The message is transmitted at the next scheduled broadcast tick.
func (n *Node) Send(recipientPubHex string, content string) error {
	return n.sendTyped(recipientPubHex, MsgTypeDirect, content)
}

// sendTyped is the internal send with explicit message type.
func (n *Node) sendTyped(recipientPubHex string, msgType MessageType, content string) error {
	recipientPub, err := crypto.PubKeyFromHex(recipientPubHex)
	if err != nil {
		return fmt.Errorf("node: invalid recipient key: %w", err)
	}

	env := Envelope{
		Type:    msgType,
		From:    n.cfg.Keys.PublicKeyHex(),
		Content: content,
	}
	envBytes, err := marshalEnvelope(env)
	if err != nil {
		return err
	}

	ct, err := crypto.Encrypt(recipientPub, envBytes)
	if err != nil {
		return err
	}

	pkt, err := protocol.NewPacket(protocol.TypeMessage, protocol.DefaultTTL, ct)
	if err != nil {
		return err
	}

	select {
	case n.sendQ <- pkt:
		return nil
	default:
		return fmt.Errorf("node: send queue full")
	}
}

// SendWrapped sends a double-wrapped "forward" packet: the outer layer is
// encrypted to relayPubHex, instructing that node to re-broadcast the inner
// packet (encrypted to recipientPubHex). This hides the sender's origin.
func (n *Node) SendWrapped(relayPubHex, recipientPubHex, content string) error {
	recipientPub, err := crypto.PubKeyFromHex(recipientPubHex)
	if err != nil {
		return err
	}
	relayPub, err := crypto.PubKeyFromHex(relayPubHex)
	if err != nil {
		return err
	}

	// Build inner: only the ciphertext (not a full packet).
	// The relay will wrap it in a fresh packet when re-broadcasting.
	// This keeps the forward envelope small enough to fit in one packet.
	innerEnv := Envelope{Type: MsgTypeDirect, From: n.cfg.Keys.PublicKeyHex(), Content: content}
	innerBytes, _ := marshalEnvelope(innerEnv)
	innerCT, err := crypto.Encrypt(recipientPub, innerBytes)
	if err != nil {
		return err
	}

	// Build outer: forward instruction containing the raw inner ciphertext.
	outerEnv := Envelope{Type: MsgTypeForward, Inner: innerCT}
	outerBytes, _ := marshalEnvelope(outerEnv)
	outerCT, err := crypto.Encrypt(relayPub, outerBytes)
	if err != nil {
		return err
	}
	outerPkt, err := protocol.NewPacket(protocol.TypeMessage, protocol.DefaultTTL, outerCT)
	if err != nil {
		return err
	}

	select {
	case n.sendQ <- outerPkt:
		return nil
	default:
		return fmt.Errorf("node: send queue full")
	}
}

// RegisterName broadcasts a signed directory entry for name → this node's key.
func (n *Node) RegisterName(name string) error {
	e := &directory.Entry{
		Name:    name,
		EncPub:  n.cfg.Keys.PublicKeyHex(),
		SignPub: hex.EncodeToString(n.cfg.Keys.SignPub),
	}
	if err := e.Sign(n.cfg.Keys.SignPriv); err != nil {
		return err
	}

	// Store locally
	if n.dir != nil {
		n.dir.Add(e) //nolint:errcheck
	}

	// Broadcast to network
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	pkt, err := protocol.NewPacket(protocol.TypeDirectory, protocol.DefaultTTL, data)
	if err != nil {
		return err
	}
	select {
	case n.sendQ <- pkt:
	default:
	}
	return nil
}

// Sessions returns the node's SessionManager for TCP-over-Lethe tunneling.
func (n *Node) Sessions() *SessionManager {
	return n.sessions
}

// DialSession opens a TCP-over-Lethe session to peerPubHex on the given port.
// Implements proxy.Dialer. Returns a net.Conn bridging to the remote service.
func (n *Node) DialSession(peerPubHex string, port int) (net.Conn, error) {
	return n.sessions.Dial(peerPubHex, port)
}

// LookupName resolves a human-readable name to an enc_pub hex key.
func (n *Node) LookupName(name string) (string, bool) {
	if n.dir == nil {
		return "", false
	}
	e := n.dir.Lookup(name)
	if e == nil {
		return "", false
	}
	return e.EncPub, true
}

// broadcastLoop runs at a constant rate, emitting one packet per tick.
// It pulls from sendQ when available, otherwise emits a dummy.
func (n *Node) broadcastLoop() {
	ticker := time.NewTicker(n.cfg.Rate)
	defer ticker.Stop()
	for {
		select {
		case <-n.stopCh:
			return
		case <-ticker.C:
			var pkt protocol.Packet
			select {
			case pkt = <-n.sendQ:
				// real packet
			default:
				var err error
				pkt, err = protocol.NewDummy()
				if err != nil {
					continue
				}
			}
			// Mark as seen before broadcasting so we don't re-process our own
			n.seen.Add(pkt.Nonce)
			n.tr.Broadcast(pkt)
		}
	}
}

// receiveLoop processes packets from the transport.
func (n *Node) receiveLoop() {
	for {
		select {
		case <-n.stopCh:
			return
		case pkt := <-n.tr.Incoming():
			n.handlePacket(pkt)
		}
	}
}

func (n *Node) handlePacket(pkt protocol.Packet) {
	// 1. Deduplication
	if !n.seen.Add(pkt.Nonce) {
		return // already processed
	}

	// 2. TTL gate
	if pkt.TTL == 0 {
		return
	}
	pkt.TTL--

	// 3. Type-specific processing
	switch pkt.Type {
	case protocol.TypeDummy:
		// Dummies are re-broadcast (constant traffic invariant) but not processed.

	case protocol.TypeMessage:
		n.tryDecrypt(pkt)

	case protocol.TypeDirectory:
		if n.dir != nil {
			var e directory.Entry
			if json.Unmarshal(pkt.PayloadBytes(), &e) == nil {
				n.dir.Add(&e) //nolint:errcheck
			}
		}
	}

	// 4. Always re-broadcast (re-inject into send queue at next tick)
	select {
	case n.sendQ <- pkt:
	default:
		// Queue full; drop. The constant-rate invariant is preserved because
		// the scheduler will emit a dummy instead.
	}
}

// tryDecrypt attempts to decrypt the packet payload with the local private key.
// If it succeeds, the packet is addressed to this node; process its content.
func (n *Node) tryDecrypt(pkt protocol.Packet) {
	pt, err := crypto.Decrypt(n.cfg.Keys.EncPriv, pkt.PayloadBytes())
	if err != nil {
		// Not for us — normal and expected for the vast majority of packets.
		return
	}

	env, err := unmarshalEnvelope(pt)
	if err != nil {
		return
	}

	switch env.Type {
	case MsgTypeSession:
		n.sessions.Handle(env)
		return // don't deliver to messages channel

	case MsgTypeDirect:
		select {
		case n.messages <- IncomingMessage{From: env.From, Content: env.Content}:
		default:
		}

	case MsgTypeForward:
		// We are a relay for this packet.
		// env.Inner contains the raw ciphertext for the final recipient.
		// Wrap it in a fresh packet (new nonce, new TTL) and re-broadcast.
		// This means the inner content appears to originate from us, not the sender.
		if len(env.Inner) == 0 {
			return
		}
		innerPkt, err := protocol.NewPacket(protocol.TypeMessage, protocol.DefaultTTL, env.Inner)
		if err != nil {
			return
		}
		// Inject inner packet into send queue; it will be broadcast at next tick.
		select {
		case n.sendQ <- innerPkt:
		default:
		}

	case MsgTypeDirectoryEntry:
		if n.dir != nil {
			var e directory.Entry
			if json.Unmarshal([]byte(env.Content), &e) == nil {
				n.dir.Add(&e) //nolint:errcheck
			}
		}
	}
}
