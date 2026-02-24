package node

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Operative-001/lethe/internal/crypto"
	"github.com/Operative-001/lethe/internal/transport"
)

// startEchoServer starts a simple TCP echo server on a random port.
// Returns the port and a closer function.
func startEchoServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // echo
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return port
}

// startHTTPServer starts a local HTTP server on a random port.
// Returns the port.
func startHTTPServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello from Lethe hidden service!")
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln) //nolint:errcheck
	t.Cleanup(func() { srv.Close() })
	return port
}

func newTestNodeWithExpose(t *testing.T, exposePort int) (*Node, *transport.MemoryTransport) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	tr := transport.NewMemory()
	n, err := New(Config{
		Keys:       kp,
		Transport:  tr,
		Rate:       10 * time.Millisecond,
		ExposePort: exposePort,
	})
	if err != nil {
		t.Fatal(err)
	}
	return n, tr
}

func TestSessionEchoTunnel(t *testing.T) {
	// Start a local echo server
	echoPort := startEchoServer(t)

	// Host: exposes the echo server via Lethe
	host, hostTr := newTestNodeWithExpose(t, echoPort)
	// Client: no exposure, just dials
	client, clientTr := newTestNodeWithExpose(t, 0)

	hostTr.Connect(clientTr.ID())

	host.Start()
	client.Start()
	defer host.Stop()
	defer client.Stop()

	// Client dials host's echo service
	conn, err := client.DialSession(host.cfg.Keys.PublicKeyHex(), echoPort)
	if err != nil {
		t.Fatalf("DialSession: %v", err)
	}
	defer conn.Close()

	// Send data through the Lethe tunnel
	msg := "hello through lethe"
	conn.Write([]byte(msg)) //nolint:errcheck

	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	got := string(buf[:n])
	if !strings.Contains(got, msg) {
		t.Fatalf("echo mismatch: got %q want to contain %q", got, msg)
	}
}

func TestSessionHTTPTunnel(t *testing.T) {
	// Start a local HTTP server
	httpPort := startHTTPServer(t)

	// Host exposes local HTTP server
	host, hostTr := newTestNodeWithExpose(t, httpPort)
	client, clientTr := newTestNodeWithExpose(t, 0)

	hostTr.Connect(clientTr.ID())

	host.Start()
	client.Start()
	defer host.Stop()
	defer client.Stop()

	// Client opens a session to host's HTTP server
	conn, err := client.DialSession(host.cfg.Keys.PublicKeyHex(), httpPort)
	if err != nil {
		t.Fatalf("DialSession: %v", err)
	}
	defer conn.Close()

	// Send a raw HTTP request
	req := "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
	conn.Write([]byte(req)) //nolint:errcheck

	// Read response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	resp, err := io.ReadAll(conn)
	if err != nil && len(resp) == 0 {
		t.Fatalf("ReadAll: %v", err)
	}

	respStr := string(resp)
	if !strings.Contains(respStr, "Hello from Lethe hidden service") {
		t.Fatalf("unexpected response: %q", respStr)
	}
	t.Logf("HTTP response through Lethe:\n%s", respStr)
}

func TestSessionServiceUnavailable(t *testing.T) {
	// Host not exposing any service
	host, hostTr := newTestNodeWithExpose(t, 0) // exposePort=0
	client, clientTr := newTestNodeWithExpose(t, 0)

	hostTr.Connect(clientTr.ID())
	host.Start()
	client.Start()
	defer host.Stop()
	defer client.Stop()

	_, err := client.DialSession(host.cfg.Keys.PublicKeyHex(), 8080)
	if err == nil {
		t.Fatal("expected error when host has no exposed service")
	}
}
