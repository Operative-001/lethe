// Package protocol defines the Lethe wire format.
//
// All packets are exactly PacketSize bytes. Payloads shorter than the maximum
// are padded with random bytes; the true payload length is encoded in a
// 2-byte little-endian length prefix inside the payload region. This ensures
// every packet on the wire is indistinguishable by size regardless of content.
package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

const (
	PacketSize  = 1024
	NonceSize   = 32
	HeaderSize  = NonceSize + 1 + 1 + 2 // nonce + type + TTL + payloadLen
	MaxPayload  = PacketSize - HeaderSize

	TypeMessage  byte = 0x01 // encrypted message or forward wrapper
	TypeDirectory byte = 0x02 // key directory broadcast
	TypeDummy    byte = 0xFF // cover traffic — identical format, discarded after dedup

	DefaultTTL byte = 8
)

// Packet is a fixed-size unit of network traffic.
// Every packet, regardless of type, occupies exactly PacketSize bytes on the wire.
type Packet struct {
	Nonce      [NonceSize]byte // random; used for deduplication
	Type       byte
	TTL        byte
	PayloadLen uint16
	Payload    [MaxPayload]byte
}

var ErrInvalidSize = errors.New("packet: invalid size")

// Encode serialises p into exactly PacketSize bytes.
func (p *Packet) Encode() [PacketSize]byte {
	var buf [PacketSize]byte
	copy(buf[:NonceSize], p.Nonce[:])
	buf[NonceSize] = p.Type
	buf[NonceSize+1] = p.TTL
	binary.LittleEndian.PutUint16(buf[NonceSize+2:], p.PayloadLen)
	copy(buf[HeaderSize:], p.Payload[:])
	return buf
}

// Decode parses exactly PacketSize bytes into a Packet.
func Decode(b []byte) (Packet, error) {
	if len(b) != PacketSize {
		return Packet{}, ErrInvalidSize
	}
	var p Packet
	copy(p.Nonce[:], b[:NonceSize])
	p.Type = b[NonceSize]
	p.TTL = b[NonceSize+1]
	p.PayloadLen = binary.LittleEndian.Uint16(b[NonceSize+2:])
	if int(p.PayloadLen) > MaxPayload {
		return Packet{}, errors.New("packet: payloadLen overflows")
	}
	copy(p.Payload[:], b[HeaderSize:])
	return p, nil
}

// PayloadBytes returns the meaningful payload bytes (not the padding).
func (p *Packet) PayloadBytes() []byte {
	return p.Payload[:p.PayloadLen]
}

// NewPacket creates a packet with a fresh random nonce.
func NewPacket(typ byte, ttl byte, payload []byte) (Packet, error) {
	if len(payload) > MaxPayload {
		return Packet{}, errors.New("packet: payload exceeds MaxPayload")
	}
	p := Packet{
		Type:       typ,
		TTL:        ttl,
		PayloadLen: uint16(len(payload)),
	}
	if _, err := io.ReadFull(rand.Reader, p.Nonce[:]); err != nil {
		return Packet{}, err
	}
	copy(p.Payload[:], payload)
	// Pad remaining bytes with random data so all packets look identical
	if len(payload) < MaxPayload {
		if _, err := io.ReadFull(rand.Reader, p.Payload[len(payload):]); err != nil {
			return Packet{}, err
		}
	}
	return p, nil
}

// NewDummy returns a cover-traffic packet with a random nonce and random payload.
// It is structurally identical to a real packet.
func NewDummy() (Packet, error) {
	p := Packet{Type: TypeDummy, TTL: DefaultTTL}
	if _, err := io.ReadFull(rand.Reader, p.Nonce[:]); err != nil {
		return Packet{}, err
	}
	if _, err := io.ReadFull(rand.Reader, p.Payload[:]); err != nil {
		return Packet{}, err
	}
	return p, nil
}
