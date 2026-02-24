package protocol

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeRoundtrip(t *testing.T) {
	payload := []byte("test payload content")
	pkt, err := NewPacket(TypeMessage, DefaultTTL, payload)
	if err != nil {
		t.Fatal(err)
	}

	wire := pkt.Encode()
	if len(wire) != PacketSize {
		t.Fatalf("encoded size %d != %d", len(wire), PacketSize)
	}

	decoded, err := Decode(wire[:])
	if err != nil {
		t.Fatal(err)
	}

	if decoded.Type != TypeMessage {
		t.Fatalf("type mismatch: %d", decoded.Type)
	}
	if decoded.TTL != DefaultTTL {
		t.Fatalf("TTL mismatch: %d", decoded.TTL)
	}
	if !bytes.Equal(decoded.PayloadBytes(), payload) {
		t.Fatalf("payload mismatch: got %q want %q", decoded.PayloadBytes(), payload)
	}
	if decoded.Nonce != pkt.Nonce {
		t.Fatal("nonce mismatch")
	}
}

func TestDecodeWrongSize(t *testing.T) {
	_, err := Decode(make([]byte, 10))
	if err != ErrInvalidSize {
		t.Fatalf("expected ErrInvalidSize, got %v", err)
	}
}

func TestNewDummySize(t *testing.T) {
	d, err := NewDummy()
	if err != nil {
		t.Fatal(err)
	}
	wire := d.Encode()
	if len(wire) != PacketSize {
		t.Fatalf("dummy size %d != %d", len(wire), PacketSize)
	}
	if d.Type != TypeDummy {
		t.Fatal("dummy type wrong")
	}
}

func TestAllPacketsSameWireSize(t *testing.T) {
	// A core invariant: ALL packets must be PacketSize regardless of payload
	tests := []struct {
		name    string
		payload []byte
	}{
		{"empty", []byte{}},
		{"small", []byte("hi")},
		{"full", make([]byte, MaxPayload)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkt, err := NewPacket(TypeMessage, DefaultTTL, tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			wire := pkt.Encode()
			if len(wire) != PacketSize {
				t.Fatalf("wire size %d != %d for payload len %d", len(wire), PacketSize, len(tc.payload))
			}
		})
	}
}

func TestPayloadTooLarge(t *testing.T) {
	_, err := NewPacket(TypeMessage, DefaultTTL, make([]byte, MaxPayload+1))
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
}
