// Package proxy provides a SOCKS5 server for browser integration.
//
// Configure your browser to use SOCKS5 proxy at 127.0.0.1:1080.
// .lethe addresses (e.g. alice.lethe) are resolved via the local key directory.
// All other addresses are passed through directly (or rejected if exitPolicy=deny).
//
// Current implementation: SOCKS5 CONNECT for .lethe domains resolves the
// enc_pub key and returns a diagnostic connection. Full TCP-over-Lethe tunneling
// (streaming arbitrary TCP through the broadcast network) is tracked in v0.2.
package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

// Resolver maps .lethe hostnames to X25519 public key hex strings.
type Resolver interface {
	LookupName(name string) (encPubHex string, ok bool)
}

// Server is a minimal SOCKS5 proxy (RFC 1928, CONNECT method only).
type Server struct {
	listenAddr string
	resolver   Resolver
	allowExit  bool // if false, non-.lethe destinations are rejected
}

// New creates a SOCKS5 Server.
func New(listenAddr string, resolver Resolver, allowExit bool) *Server {
	return &Server{
		listenAddr: listenAddr,
		resolver:   resolver,
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

	// SOCKS5 handshake
	if err := s.socks5Handshake(conn); err != nil {
		return
	}

	// Read CONNECT request
	dest, err := s.readRequest(conn)
	if err != nil {
		s.writeReply(conn, 0x07) // command not supported
		return
	}

	host, _, _ := net.SplitHostPort(dest)
	isLethe := strings.HasSuffix(strings.ToLower(host), ".lethe")

	if isLethe {
		s.handleLetheConnect(conn, host)
		return
	}

	if !s.allowExit {
		s.writeReply(conn, 0x02) // connection not allowed
		return
	}

	// Pass-through to real destination
	upstream, err := net.Dial("tcp", dest)
	if err != nil {
		s.writeReply(conn, 0x05) // connection refused
		return
	}
	defer upstream.Close()

	s.writeReply(conn, 0x00) // success
	go io.Copy(upstream, conn) //nolint:errcheck
	io.Copy(conn, upstream)    //nolint:errcheck
}

// handleLetheConnect resolves the .lethe address and responds.
// In v0.1, this confirms resolution and returns the public key as a banner.
// Full TCP-over-Lethe tunneling is v0.2.
func (s *Server) handleLetheConnect(conn net.Conn, host string) {
	name := strings.TrimSuffix(strings.ToLower(host), ".lethe")
	encPub, ok := s.resolver.LookupName(name)
	if !ok {
		s.writeReply(conn, 0x04) // host unreachable
		return
	}

	s.writeReply(conn, 0x00) // success
	// Send a banner so browser shows something useful
	banner := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"+
			"Lethe node: %s\nAddress: %s.lethe\nKey: %s\n"+
			"Full TCP tunneling: v0.2\n",
		host, name, encPub,
	)
	conn.Write([]byte(banner)) //nolint:errcheck
}

// socks5Handshake negotiates no-auth (method 0x00).
func (s *Server) socks5Handshake(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if buf[0] != 0x05 {
		return fmt.Errorf("proxy: not SOCKS5")
	}
	nmethods := int(buf[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	// Accept no-auth
	conn.Write([]byte{0x05, 0x00}) //nolint:errcheck
	return nil
}

// readRequest reads a SOCKS5 CONNECT request and returns "host:port".
func (s *Server) readRequest(conn net.Conn) (string, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "", err
	}
	if hdr[0] != 0x05 || hdr[1] != 0x01 {
		return "", fmt.Errorf("proxy: only CONNECT supported")
	}

	var host string
	switch hdr[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		io.ReadFull(conn, addr) //nolint:errcheck
		host = net.IP(addr).String()
	case 0x03: // domain name
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf) //nolint:errcheck
		domain := make([]byte, int(lenBuf[0]))
		io.ReadFull(conn, domain) //nolint:errcheck
		host = string(domain)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		io.ReadFull(conn, addr) //nolint:errcheck
		host = net.IP(addr).String()
	default:
		return "", fmt.Errorf("proxy: unknown address type %d", hdr[3])
	}

	portBuf := make([]byte, 2)
	io.ReadFull(conn, portBuf) //nolint:errcheck
	port := binary.BigEndian.Uint16(portBuf)

	return fmt.Sprintf("%s:%d", host, port), nil
}

// writeReply sends a SOCKS5 reply with the given status code.
func (s *Server) writeReply(conn net.Conn, status byte) {
	// VER REP RSV ATYP BND.ADDR BND.PORT
	reply := []byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(reply) //nolint:errcheck
}
