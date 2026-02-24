# Lethe

**The network that forgets.**

Anonymous peer-to-peer communication where no node — not even one controlled by a nation-state with full backbone access — can determine who is talking to whom.

```bash
# Install
go install github.com/Operative-001/lethe/cmd/lethe@latest

# One command to start
lethe keygen && lethe daemon
```

Set your browser's SOCKS5 proxy to `127.0.0.1:1080`. Done.

---

## The Problem With Every Other Approach

| Tool       | What They Know About You                                                  |
|------------|---------------------------------------------------------------------------|
| Signal     | Your phone number. Who you message. When. How often.                      |
| Tor        | Guard node sees your IP. Exit node sees your destination.                 |
| I2P        | Entry/exit guards. NetDB directory servers. Complex tunnel metadata.      |
| VPN        | Your provider sees everything. One subpoena away from full exposure.      |
| Telegram   | Your phone, IP, all messages. Contacts graph. Location metadata.          |

The root problem: **every existing system has asymmetry**. There is a "client" (identified) connecting to a "server" (known). Anonymity tools try to hide one or the other, but the structural asymmetry remains.

Lethe eliminates the asymmetry entirely.

---

## How It Works

Every node does three things, always, unconditionally:

### 1. Constant-Rate Traffic

```
Node A: ████████████████████████████████  (10 packets/sec, always)
Node B: ████████████████████████████████  (10 packets/sec, always)
Node C: ████████████████████████████████  (10 packets/sec, always)
```

Most of these packets are **dummies** — cryptographically indistinguishable from real messages. When a real message exists, it **replaces** a dummy in the pre-committed queue. From the outside: constant noise, forever. There is no traffic spike when you send. There is no silence when you don't.

### 2. Broadcast Delivery

Every packet goes to every node. There are no routing tables, no paths, no circuits, no guards, no exits. The network topology is flat. Every node is simultaneously a sender, relay, and potential recipient.

```
Alice sends → every node receives the same packet
              ↓
              Each node tries to decrypt with its private key
              Only Bob's key produces a valid authentication tag
              Bob receives. Alice is invisible.
```

### 3. Recipient Anonymity via Asymmetric Decryption

Your **public key is your address**. Messages are encrypted to your key using ECIES (X25519 + ChaCha20-Poly1305). Every node receives every packet and attempts decryption. For 99.99% of nodes, decryption fails — expected and normal. For the recipient, it succeeds.

No node ever knows who a packet is addressed to. Not the relays. Not the ISP watching the wire. Not a global passive adversary watching all traffic simultaneously.

---

## Sender Anonymity: The Wrap-and-Forward Layer

Sending a message directly would expose your IP as the origination point. Lethe prevents this with **double-layer encryption**:

```
Alice wants to message Bob:

1. Alice encrypts inner payload to Bob's key
2. Alice wraps it in an outer layer encrypted to Relay R's key
   Outer payload = { "forward": <inner packet> }

3. Alice sends the outer packet to R
   → From the network's view: R is the origin of the inner packet

4. R decrypts outer layer, sees "forward this"
   → Re-broadcasts inner packet at its own next scheduled tick
   → Indistinguishable from R's own outbound traffic

5. Every node receives inner packet
   → Bob decrypts successfully
   → No node knows Alice originated this
```

Since all nodes are **always** doing wrap-and-forward as part of their normal operation, Alice's outbound packet is invisible in the constant stream.

---

## Why Nation-State Attacks Fail

### ❌ Traffic volume analysis
All nodes emit constant traffic regardless of real message load. There is no signal in volume.

### ❌ Propagation origin tracking
The network-observable origin of any packet is the wrap-and-forward relay, not the true sender. Multiple relays can be chained.

### ❌ Intersection attacks (offline correlation)
No store-and-forward. If the recipient is offline, the message is not delivered. There is no "Bob came online and processed queued messages" signal to observe.

### ❌ Confirmation attacks ("I sent to key X, who reacted?")
Because every node re-broadcasts every packet regardless of whether they could decrypt it, no node's behavior changes on receipt. The recipient's re-broadcast is indistinguishable from the relay's re-broadcast.

### ❌ Long-term relay correlation
Every node randomly selects different relays per message. No persistent Alice→Relay relationship exists to observe statistically.

### ✓ Remaining challenge: bootstrap moment
When first joining, a new node must contact bootstrap peers (revealing IP to those specific peers). Mitigated by bootstrapping over Tor or using multiple bootstrap nodes across jurisdictions.

### ✓ Remaining challenge: global timing with zero cover traffic
If a node sends messages but never maintains cover traffic (violates protocol), statistical timing attacks are possible over thousands of messages. The protocol mandates constant traffic; compliant nodes are protected.

---

## Quick Start

### Install

```bash
go install github.com/Operative-001/lethe/cmd/lethe@latest
```

Or build from source:
```bash
git clone https://github.com/Operative-001/lethe
cd lethe
make install
```

### Run

```bash
# Generate your identity (one time)
lethe keygen

# Start the node — proxy is immediately available on :1080
lethe daemon

# With bootstrap peers (to join an existing network)
lethe daemon --bootstrap "peer1.example.com:4242,peer2.example.com:4242"
```

### Configure Your Browser

**Firefox**: Settings → Network → Manual proxy → SOCKS5: `127.0.0.1:1080`

**Chrome/Chromium**:
```bash
chromium --proxy-server="socks5://127.0.0.1:1080"
```

### Send Messages

From the daemon interactive console, or in a separate terminal:

```bash
# Register your name (broadcasts to network)
lethe register alice

# Send to a registered name
lethe send bob "hello"

# Send to a raw public key
lethe send a3f4b2c1d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2 "hello"
```

### Connect Two Nodes Locally (for testing)

```bash
# Terminal 1 — Alice
lethe keygen --data /tmp/alice
lethe daemon --data /tmp/alice --listen 0.0.0.0:4242 --proxy 127.0.0.1:1080

# Terminal 2 — Bob
lethe keygen --data /tmp/bob
lethe daemon --data /tmp/bob --listen 0.0.0.0:4243 --proxy 127.0.0.1:1081 \
  --bootstrap 127.0.0.1:4242

# From Bob's console: type 'send <alice-pubkey> hello alice'
```

---

## Protocol at a Glance

| Property                    | Value                                          |
|-----------------------------|------------------------------------------------|
| Packet size                 | Fixed 1024 bytes (uniform, no size leakage)     |
| Symmetric encryption        | ChaCha20-Poly1305                              |
| Key agreement               | X25519 ECDH (ephemeral per message)            |
| Key derivation              | HKDF-SHA256                                    |
| Signing                     | Ed25519 (directory entries only)               |
| Transport                   | TCP (pluggable)                                |
| Broadcast rate              | 10 packets/sec per node (configurable)         |
| TTL                         | 8 hops default                                 |
| Deduplication               | 32-byte nonce ring buffer, 60s expiry          |
| Directory                   | Local bbolt DB, broadcast-synchronized         |
| Identity                    | X25519 pubkey = address (no username required) |

Full specification: [PROTOCOL.md](PROTOCOL.md)

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     lethe daemon                        │
│                                                         │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────┐  │
│  │  Broadcast  │    │     Node     │    │  SOCKS5   │  │
│  │  Scheduler  │◄───│   Engine     │───►│   Proxy   │  │
│  │  10 pkt/s   │    │              │    │ :1080     │  │
│  └─────────────┘    └──────┬───────┘    └───────────┘  │
│                             │                           │
│                    ┌────────┴────────┐                  │
│                    │                 │                  │
│              ┌─────┴───┐    ┌────────┴──┐              │
│              │  Seen   │    │ Directory │              │
│              │  Cache  │    │  (bbolt)  │              │
│              └─────────┘    └───────────┘              │
└─────────────────────────┬───────────────────────────────┘
                          │ TCP transport
                   ┌──────┴──────┐
                   │  Peer mesh  │
                   └─────────────┘
```

---

## Security Model

**What Lethe protects against:**
- Network-level observers (ISPs, backbone taps)
- Compromised relay nodes
- Statistical traffic analysis
- Confirmation attacks by active adversaries
- Timing correlation for compliant nodes

**What Lethe does NOT protect against:**
- Endpoint compromise (if your device is owned, you're owned)
- Bootstrap phase IP exposure (mitigate: bootstrap over Tor)
- Long-term statistical attacks against non-compliant nodes (nodes that don't maintain cover traffic)
- Quantum computers breaking X25519 (future: upgrade to post-quantum KEM)

---

## Development

```bash
# Run all tests
make test

# Run tests with race detector
make test-race

# Build binary
make build

# Install
make install
```

### Test Coverage

```
internal/crypto     — ECIES roundtrip, wrong key, key save/load
internal/protocol   — packet encode/decode, size invariant
internal/seen       — add/has, expiry, concurrent access
internal/directory  — signature verification, timestamp ordering
internal/node       — direct delivery, wrap-and-forward, deduplication, TTL
```

---

## Roadmap

- **v0.1** (current): Core protocol, CLI, SOCKS5 proxy with .lethe address resolution
- **v0.2**: Full TCP-over-Lethe tunneling (arbitrary HTTP/TCP through the network), daemon IPC socket for `lethe send` without console
- **v0.3**: Mobile library (iOS/Android via gomobile)
- **v0.4**: Post-quantum key encapsulation (ML-KEM / Kyber-1024)
- **v0.5**: Chaumian batch mixing mode for maximum anonymity (adds latency)

---

## Name

**Lethe** (λήθη) — in Greek mythology, one of the five rivers of the underworld. Souls who drank from it forgot all earthly memories. The network forgets everything: who sent, who received, when, how often.

---

## License

MIT
