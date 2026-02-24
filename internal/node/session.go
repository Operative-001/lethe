package node

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// SessionMsg is the JSON structure for session control/data messages.
// These are carried inside the standard Envelope as the Content field.
type SessionMsg struct {
	Type    string `json:"t"`
	SID     string `json:"sid"`          // session ID (random 16-byte hex)
	From    string `json:"from"`         // sender's enc_pub hex
	Port    int    `json:"port,omitempty"` // session_open: target service port
	Seq     uint32 `json:"seq,omitempty"`
	Data    []byte `json:"data,omitempty"` // session_data: raw bytes chunk
	Reason  string `json:"reason,omitempty"` // session_close: reason
}

const (
	SessOpen  = "session_open"
	SessData  = "session_data"
	SessClose = "session_close"
)

// MaxChunkSize is the maximum raw bytes per session_data packet.
// Chosen to keep the full encrypted Lethe packet within MaxPayload.
const MaxChunkSize = 512

// session tracks one end of an active TCP-over-Lethe tunnel.
type session struct {
	id       string
	peerKey  string      // enc_pub of the remote party
	conn     net.Conn    // local TCP connection (nil on client side until established)
	dataCh   chan []byte  // incoming data from remote peer
	closeCh  chan struct{}
	once     sync.Once
}

func (s *session) close() {
	s.once.Do(func() {
		close(s.closeCh)
		if s.conn != nil {
			s.conn.Close()
		}
	})
}

// SessionManager handles all active sessions for a node.
type SessionManager struct {
	node        *Node
	exposedPort int // local port to expose as a hidden service (0 = not hosting)

	mu       sync.Mutex
	sessions map[string]*session

	// pending holds sessions waiting for the first response (client side).
	// Key = session ID. nil error = connected; non-nil = rejected/closed.
	pending map[string]chan error
}

func newSessionManager(n *Node, exposedPort int) *SessionManager {
	return &SessionManager{
		node:        n,
		exposedPort: exposedPort,
		sessions:    make(map[string]*session),
		pending:     make(map[string]chan error),
	}
}

// newSessionID generates a random 16-byte hex session ID.
func newSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Dial initiates a session to a remote service identified by peerPubHex.
// Returns a net.Conn that bridges to the remote service.
// Used by the SOCKS5 proxy on the client side.
func (sm *SessionManager) Dial(peerPubHex string, port int) (net.Conn, error) {
	sid, err := newSessionID()
	if err != nil {
		return nil, err
	}

	sess := &session{
		id:      sid,
		peerKey: peerPubHex,
		dataCh:  make(chan []byte, 64),
		closeCh: make(chan struct{}),
	}

	established := make(chan error, 1)

	sm.mu.Lock()
	sm.sessions[sid] = sess
	sm.pending[sid] = established
	sm.mu.Unlock()

	// Send session_open to remote peer
	openMsg := SessionMsg{
		Type: SessOpen,
		SID:  sid,
		From: sm.node.cfg.Keys.PublicKeyHex(),
		Port: port,
	}
	if err := sm.sendSessionMsg(peerPubHex, openMsg); err != nil {
		sm.removeSession(sid)
		return nil, fmt.Errorf("session dial: %w", err)
	}

	// Wait for the remote side to acknowledge (session_data ack) or reject (session_close).
	select {
	case err := <-established:
		if err != nil {
			sm.removeSession(sid)
			return nil, fmt.Errorf("session dial: remote rejected: %w", err)
		}
		// Connection confirmed — return a virtual conn
	case <-time.After(10 * time.Second):
		sm.removeSession(sid)
		return nil, fmt.Errorf("session dial: timeout waiting for remote")
	}

	sm.mu.Lock()
	delete(sm.pending, sid)
	sm.mu.Unlock()

	return newLetheConn(sess, sm, peerPubHex), nil
}

// Handle processes an incoming session message decoded from a Lethe packet.
func (sm *SessionManager) Handle(env Envelope) {
	var msg SessionMsg
	if err := json.Unmarshal([]byte(env.Content), &msg); err != nil {
		return
	}
	msg.From = env.From // use the envelope's From field as authoritative sender key

	switch msg.Type {
	case SessOpen:
		sm.handleOpen(msg)
	case SessData:
		sm.handleData(msg)
	case SessClose:
		sm.handleClose(msg)
	}
}

// handleOpen processes an incoming session_open request (host side).
func (sm *SessionManager) handleOpen(msg SessionMsg) {
	if sm.exposedPort == 0 {
		// Not hosting — send back a close
		sm.sendSessionMsg(msg.From, SessionMsg{ //nolint:errcheck
			Type:   SessClose,
			SID:    msg.SID,
			From:   sm.node.cfg.Keys.PublicKeyHex(),
			Reason: "service not available",
		})
		return
	}

	// Dial local service
	target := fmt.Sprintf("127.0.0.1:%d", sm.exposedPort)
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		sm.sendSessionMsg(msg.From, SessionMsg{ //nolint:errcheck
			Type:   SessClose,
			SID:    msg.SID,
			From:   sm.node.cfg.Keys.PublicKeyHex(),
			Reason: "local service unavailable",
		})
		return
	}

	sess := &session{
		id:      msg.SID,
		peerKey: msg.From,
		conn:    conn,
		dataCh:  make(chan []byte, 64),
		closeCh: make(chan struct{}),
	}

	sm.mu.Lock()
	sm.sessions[msg.SID] = sess
	sm.mu.Unlock()

	// ACK: send empty session_data back to the dialer so Dial() unblocks.
	// Without this, the client waits indefinitely for the first data byte.
	sm.sendSessionMsg(msg.From, SessionMsg{ //nolint:errcheck
		Type: SessData,
		SID:  msg.SID,
		From: sm.node.cfg.Keys.PublicKeyHex(),
		Seq:  0,
		Data: nil, // empty = connection established signal
	})

	// Bridge: local conn → Lethe (read from local, send to remote)
	go sm.bridgeLocalToLethe(sess)
	// Bridge: Lethe → local conn (handled by handleData writing to sess.conn)
}

// handleData delivers incoming data to the right session.
func (sm *SessionManager) handleData(msg SessionMsg) {
	sm.mu.Lock()
	sess, ok := sm.sessions[msg.SID]
	pendingCh := sm.pending[msg.SID]
	sm.mu.Unlock()

	if !ok {
		return
	}

	// If this is the first data and there's a pending Dial waiting, signal success
	if pendingCh != nil {
		select {
		case pendingCh <- nil: // nil = connected successfully
		default:
		}
	}

	// Deliver data
	if len(msg.Data) > 0 {
		if sess.conn != nil {
			// Host side or client side with direct conn
			sess.conn.Write(msg.Data) //nolint:errcheck
		} else {
			// Client side: deliver to dataCh for LetheConn.Read()
			select {
			case sess.dataCh <- msg.Data:
			default:
			}
		}
	}
}

// handleClose tears down a session.
func (sm *SessionManager) handleClose(msg SessionMsg) {
	sm.mu.Lock()
	sess, ok := sm.sessions[msg.SID]
	pendingCh := sm.pending[msg.SID]
	sm.mu.Unlock()

	if pendingCh != nil {
		reason := msg.Reason
		if reason == "" {
			reason = "remote closed connection"
		}
		select {
		case pendingCh <- fmt.Errorf("%s", reason):
		default:
		}
	}

	if ok {
		sess.close()
		sm.removeSession(msg.SID)
	}
}

// bridgeLocalToLethe reads from the local TCP connection and sends data via Lethe.
func (sm *SessionManager) bridgeLocalToLethe(sess *session) {
	defer func() {
		sm.sendSessionMsg(sess.peerKey, SessionMsg{ //nolint:errcheck
			Type: SessClose,
			SID:  sess.id,
			From: sm.node.cfg.Keys.PublicKeyHex(),
		})
		sess.close()
		sm.removeSession(sess.id)
	}()

	buf := make([]byte, MaxChunkSize)
	var seq uint32
	for {
		select {
		case <-sess.closeCh:
			return
		default:
		}

		sess.conn.SetReadDeadline(time.Now().Add(30 * time.Second)) //nolint:errcheck
		n, err := sess.conn.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			sm.sendSessionMsg(sess.peerKey, SessionMsg{ //nolint:errcheck
				Type: SessData,
				SID:  sess.id,
				From: sm.node.cfg.Keys.PublicKeyHex(),
				Seq:  seq,
				Data: chunk,
			})
			seq++
		}
		if err != nil {
			return
		}
	}
}

func (sm *SessionManager) sendSessionMsg(toPubHex string, msg SessionMsg) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return sm.node.sendTyped(toPubHex, MsgTypeSession, string(b))
}

func (sm *SessionManager) removeSession(sid string) {
	sm.mu.Lock()
	delete(sm.sessions, sid)
	delete(sm.pending, sid)
	sm.mu.Unlock()
}

// ─── LetheConn ───────────────────────────────────────────────────────────────

// letheConn implements net.Conn for the client side of a Lethe session.
// Reads come from the session's dataCh; writes are sent via Lethe messages.
type letheConn struct {
	sess    *session
	sm      *SessionManager
	peerKey string

	readBuf []byte
	mu      sync.Mutex
}

func newLetheConn(sess *session, sm *SessionManager, peerKey string) *letheConn {
	return &letheConn{sess: sess, sm: sm, peerKey: peerKey}
}

func (c *letheConn) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.readBuf) > 0 {
			n := copy(b, c.readBuf)
			c.readBuf = c.readBuf[n:]
			c.mu.Unlock()
			return n, nil
		}
		c.mu.Unlock()

		select {
		case <-c.sess.closeCh:
			return 0, io.EOF
		case data := <-c.sess.dataCh:
			c.mu.Lock()
			c.readBuf = append(c.readBuf, data...)
			c.mu.Unlock()
		case <-time.After(60 * time.Second):
			return 0, fmt.Errorf("lethe: read timeout")
		}
	}
}

func (c *letheConn) Write(b []byte) (int, error) {
	// Chunk into MaxChunkSize pieces
	sent := 0
	for len(b) > 0 {
		chunk := b
		if len(chunk) > MaxChunkSize {
			chunk = b[:MaxChunkSize]
		}
		msg := SessionMsg{
			Type: SessData,
			SID:  c.sess.id,
			From: c.sm.node.cfg.Keys.PublicKeyHex(),
			Data: chunk,
		}
		if err := c.sm.sendSessionMsg(c.peerKey, msg); err != nil {
			return sent, err
		}
		sent += len(chunk)
		b = b[len(chunk):]
	}
	return sent, nil
}

func (c *letheConn) Close() error {
	c.sm.sendSessionMsg(c.peerKey, SessionMsg{ //nolint:errcheck
		Type: SessClose,
		SID:  c.sess.id,
		From: c.sm.node.cfg.Keys.PublicKeyHex(),
	})
	c.sess.close()
	c.sm.removeSession(c.sess.id)
	return nil
}

func (c *letheConn) LocalAddr() net.Addr             { return &net.TCPAddr{} }
func (c *letheConn) RemoteAddr() net.Addr            { return &net.TCPAddr{} }
func (c *letheConn) SetDeadline(t time.Time) error      { return nil }
func (c *letheConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *letheConn) SetWriteDeadline(t time.Time) error { return nil }
