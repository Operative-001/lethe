# Lethe Protocol Specification — v0.1

## Overview

Lethe is a broadcast anonymous communication protocol. The core invariant is:

> **All nodes emit a constant stream of fixed-size packets regardless of whether they have real traffic to send. Every packet is broadcast to all peers. Recipients are identified by their ability to decrypt, not by routing metadata.**

## Packet Format

All packets are exactly **1024 bytes** on the wire. Fixed size is mandatory — variable-length packets leak information about message size and type.

```
Offset  Size  Field
──────────────────────────────────────────────────────
0       32    Nonce     — random bytes, used for deduplication
32      1     Type      — 0x01=message, 0x02=directory, 0xFF=dummy
33      1     TTL       — hop counter, default 8, decremented each hop
34      2     PayLen    — little-endian uint16, length of meaningful payload
36      476   Payload   — encrypted content, padded to fill remaining bytes
```

Padding bytes (after `Payload[0:PayLen]`) MUST be random, not zero, to prevent distinguishing padded packets from full ones.

## Encryption

### Key Types

Each identity holds two keypairs:
- **X25519** (32-byte pubkey): used as the network address and for ECIES encryption
- **Ed25519** (32-byte pubkey): used exclusively for signing directory entries

### ECIES Construction

```
Encrypt(recipientPub [32]byte, plaintext []byte) → ciphertext:

1. Generate ephemeral X25519 keypair (ephPriv, ephPub)
   Clamp ephPriv: ephPriv[0] &= 248; ephPriv[31] &= 127; ephPriv[31] |= 64

2. shared = X25519(ephPriv, recipientPub)

3. key = HKDF-SHA256(ikm=shared, salt=ephPub[0:8], info="lethe-v1")[0:32]

4. nonce = random 12 bytes

5. ct = ChaCha20-Poly1305(key, nonce, plaintext, aad=nil)

6. output = ephPub(32) || nonce(12) || ct+tag(len(plaintext)+16)
```

```
Decrypt(privKey [32]byte, data []byte) → plaintext | ErrDecryptFailed:

1. ephPub = data[0:32]
2. nonce  = data[32:44]
3. ct     = data[44:]
4. shared = X25519(privKey, ephPub)
5. key    = HKDF-SHA256(ikm=shared, salt=ephPub[0:8], info="lethe-v1")[0:32]
6. plaintext, err = ChaCha20-Poly1305.Open(key, nonce, ct, aad=nil)
   if err != nil → return ErrDecryptFailed  ← "not for me"
```

**ErrDecryptFailed is not an error condition.** Every node receives every packet and attempts decryption. Failure is expected and normal for the vast majority of packets.

## Payload Envelope

The plaintext inside an encrypted payload is JSON:

```json
{ "type": "msg",
  "from": "<enc_pub_hex>",
  "content": "<message text>" }

{ "type": "forward",
  "inner": <bytes of inner Packet, exactly 512 bytes> }

{ "type": "directory",
  "content": "<JSON-encoded directory.Entry>" }
```

- `"msg"`: a direct message for the decrypting node
- `"forward"`: relay instruction; decrypting node re-broadcasts `inner` as a new packet
- `"directory"`: key registration broadcast

## Broadcast Rule

Upon receiving any packet P:

1. Check `seen[P.Nonce]` — if present, **drop silently**
2. Add `P.Nonce` to seen cache (60s TTL)
3. If `P.TTL == 0` — **drop**
4. Decrement `P.TTL`
5. If `P.Type == TypeMessage`:
   - Attempt `Decrypt(localPrivKey, P.Payload[0:P.PayLen])`
   - On success: process envelope content
   - On failure: no action (expected)
6. If `P.Type == TypeDirectory`:
   - Parse and validate directory entry
   - Store if signature valid and timestamp newer
7. Enqueue P for re-broadcast at next scheduled tick (regardless of step 5/6 outcome)

**The re-broadcast step is unconditional.** A node that successfully decrypts a message MUST still re-broadcast it. This ensures the recipient is indistinguishable from a relay.

## Constant-Rate Scheduler

Each node maintains a send queue and a rate ticker:

```
every 1/rate seconds:
  if sendQueue non-empty:
    dequeue P
    broadcast P
  else:
    P = NewDummy()  ← random nonce, TypeDummy, random payload
    broadcast P
```

The rate MUST be constant. Implementations MUST NOT:
- Burst multiple packets at once
- Slow down when the queue is empty (send dummies instead)
- Skip ticks for any reason

## Wrap-and-Forward (Sender Anonymity)

To hide the sender's origin, messages are double-wrapped:

```
Outer packet:
  Encrypted to relay R's pubkey
  Payload: { "type": "forward", "inner": <inner packet bytes> }

Inner packet:
  Encrypted to recipient's pubkey
  Payload: { "type": "msg", "from": "...", "content": "..." }
```

Alice sends the outer packet to R. R decrypts, sees "forward", injects the inner packet into its own broadcast queue. From the network's perspective, R originated the inner packet.

For maximum anonymity, chain multiple relays: Alice → R1 → R2 → Bob. Each layer adds a forward wrapper.

## Key Directory

The key directory maps human-readable names to X25519 public keys. All nodes maintain an identical local copy, synchronized via the broadcast stream.

### Entry Format

```json
{
  "name": "alice",
  "enc_pub": "<32-byte X25519 pubkey hex>",
  "sign_pub": "<32-byte Ed25519 pubkey hex>",
  "timestamp": 1234567890,
  "sig": "<Ed25519 signature over canonical JSON>"
}
```

Canonical form for signing (fields in this order, no sig field):
```json
{"name":"alice","enc_pub":"...","sign_pub":"...","timestamp":1234567890}
```

### Directory Rules

1. Entries with invalid signatures MUST be rejected
2. Entries with `timestamp ≤ existing.timestamp` MUST be ignored (replay protection)
3. Directory entries are broadcast in `TypeDirectory` packets and also carried as `"directory"` envelopes inside encrypted packets

### Lookup Privacy

Because every node holds a complete local copy of the directory, name lookups generate zero network traffic. There is no observable query that reveals who you are communicating with.

## TTL

Default TTL is 8. This means a packet can traverse at most 8 hops before being dropped. With a network diameter of N nodes, TTL should be set to at least `ceil(log2(N)) + 2`.

TTL prevents infinite re-broadcast loops. Combined with the seen-nonce cache (60s), packets die naturally without any node needing to "stop" propagation.

## Bootstrap

New nodes need at least one peer address to join the network. Bootstrap peers are specified at startup. The bootstrap process:

1. Connect to bootstrap peer via TCP
2. Exchange public keys (plain, unencrypted — IP is already visible to bootstrap peer)
3. Begin receiving broadcast stream
4. Directory synchronizes automatically as directory packets arrive

**Privacy implication**: the bootstrap peer learns your IP. To mitigate:
- Use multiple bootstrap nodes across different jurisdictions
- Bootstrap over Tor (connect to bootstrap peer via SOCKS5 proxy to Tor)
- Operate bootstrap nodes as hidden services

## Wire Framing

TCP connections use a 2-byte big-endian length prefix before each packet:
```
[length: 2 bytes big-endian][packet: 512 bytes]
```

Length is always 512 for compliant implementations. Connections sending wrong-length frames MUST be dropped.

## Security Properties

| Property                    | Status   | Notes                                              |
|-----------------------------|----------|----------------------------------------------------|
| Message confidentiality     | ✓        | ChaCha20-Poly1305, 256-bit key                    |
| Sender anonymity            | ✓        | Wrap-and-forward; relay is observable origin       |
| Recipient anonymity         | ✓        | Broadcast + ECIES; no routing metadata             |
| Forward secrecy             | ✓        | Ephemeral X25519 per message                      |
| Replay protection           | ✓        | Nonce cache (seen filter) + Ed25519-signed dir entries |
| Traffic analysis resistance | ✓        | Constant rate; fixed packet size; dummy traffic   |
| Intersection attack resistance | ✓     | No store-and-forward; offline = undeliverable     |
| Quantum resistance          | ✗ (v0.4) | X25519 is vulnerable to Shor's algorithm          |
| Global passive adversary    | partial  | Timing correlation across bootstrap still possible |
