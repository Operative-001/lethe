// Package proxy provides a SOCKS5 server for browser integration.
//
// Configure your browser to use SOCKS5 proxy at 127.0.0.1:1080.
//
// .lethe addresses (e.g. alice.lethe or <pubkey>.lethe) are routed through
// the Lethe anonymous network using the TCP-over-Lethe session protocol.
// The connection is bidirectional and supports arbitrary HTTP/TCP traffic.
//
// Non-.lethe addresses are either passed through (allowExit=true) or rejected.
package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

// Dialer abstracts the TCP-over-Lethe session dialer.
type Dialer interface {
	// LookupName resolves a .lethe name to an enc_pub hex key.
	LookupName(name string) (encPubHex string, ok bool)
	// DialSession opens a TCP-over-Lethe session to the given enc_pub.
	DialSession(peerPubHex string, port int) (net.Conn, error)
}

// Server is a minimal SOCKS5 proxy (RFC 1928, CONNECT method only).
type Server struct {
	listenAddr string
	dialer     Dialer
	allowExit  bool
}

// New creates a SOCKS5 Server.
func New(listenAddr string, dialer Dialer, allowExit bool) *Server {
	return &Server{
		listenAddr: listenAddr,
		dialer:     dialer,
		allowExit:  allowExit,
	}
}

// ListenAndServe starts the SOCKS5 server. Blocks until error.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	log.Printf("proxy: SOCKS5 listening on %s", s.listenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	if err := s.socks5Handshake(conn); err != nil {
		return
	}

	dest, port, err := s.readRequest(conn)
	if err != nil {
		s.writeReply(conn, 0x07)
		return
	}

	host := dest
	isLethe := strings.HasSuffix(strings.ToLower(host), ".lethe")

	if isLethe {
		s.handleLetheConnect(conn, host, port)
		return
	}

	if !s.allowExit {
		s.writeReply(conn, 0x02) // connection not allowed
		return
	}

	upstream, err := net.Dial("tcp", fmt.Sprintf("%s:%d", dest, port))
	if err != nil {
		s.writeReply(conn, 0x05)
		return
	}
	defer upstream.Close()

	s.writeReply(conn, 0x00)
	go io.Copy(upstream, conn) //nolint:errcheck
	io.Copy(conn, upstream)    //nolint:errcheck
}

// handleLetheConnect resolves the .lethe name, opens a Lethe session, and
// bridges the browser's TCP connection bidirectionally through it.
func (s *Server) handleLetheConnect(conn net.Conn, host string, port int) {
	name := strings.TrimSuffix(strings.ToLower(host), ".lethe")

	// Resolve: try directory lookup first, then treat as raw pubkey
	encPub, ok := s.dialer.LookupName(name)
	if !ok {
		// name might be a raw pubkey hex
		if len(name) == 64 {
			encPub = name
		} else {
			s.writeReply(conn, 0x04) // host unreachable
			log.Printf("proxy: unknown .lethe address: %s", name)
			return
		}
	}

	// Open TCP-over-Lethe session
	letheConn, err := s.dialer.DialSession(encPub, port)
	if err != nil {
		s.writeReply(conn, 0x05) // connection refused
		log.Printf("proxy: lethe dial %s: %v", host, err)
		return
	}
	defer letheConn.Close()

	// Tell browser: connection established
	s.writeReply(conn, 0x00)

	// Bidirectional bridge: browser ↔ Lethe session
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(letheConn, conn) //nolint:errcheck
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, letheConn) //nolint:errcheck
		done <- struct{}{}
	}()
	<-done // close when either direction ends
}

func (s *Server) socks5Handshake(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if buf[0] != 0x05 {
		return fmt.Errorf("not SOCKS5")
	}
	nmethods := int(buf[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	conn.Write([]byte{0x05, 0x00}) //nolint:errcheck
	return nil
}

func (s *Server) readRequest(conn net.Conn) (host string, port int, err error) {
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 || hdr[1] != 0x01 {
		err = fmt.Errorf("only CONNECT supported")
		return
	}

	switch hdr[3] {
	case 0x01:
		addr := make([]byte, 4)
		io.ReadFull(conn, addr) //nolint:errcheck
		host = net.IP(addr).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf) //nolint:errcheck
		domain := make([]byte, int(lenBuf[0]))
		io.ReadFull(conn, domain) //nolint:errcheck
		host = string(domain)
	case 0x04:
		addr := make([]byte, 16)
		io.ReadFull(conn, addr) //nolint:errcheck
		host = net.IP(addr).String()
	default:
		err = fmt.Errorf("unknown address type %d", hdr[3])
		return
	}

	portBuf := make([]byte, 2)
	io.ReadFull(conn, portBuf) //nolint:errcheck
	port = int(binary.BigEndian.Uint16(portBuf))
	return
}

func (s *Server) writeReply(conn net.Conn, status byte) {
	reply := []byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(reply) //nolint:errcheck
}
