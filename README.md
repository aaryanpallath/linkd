# linkd — Reliable, Precedence-Aware, Authenticated Messaging over Lossy Tactical Links (Rust)

A messaging layer for degraded radio links: an authenticated binary frame format, selective-repeat ARQ with an
RFC 6298 retransmission timer, military-style message precedence (FLASH, IMMEDIATE, PRIORITY, ROUTINE), and
exactly-once delivery. The protocol is a **sans-IO state machine**, so the same code runs in a deterministic link
simulator and over real UDP on its own threads. No `unsafe`; malformed, forged or replayed input never panics and
never changes state.

## Results

Simulated 64 kbit/s radio link, 60–100 ms one-way delay (jitter causes reordering), 2,000 messages of 200 bytes
offered at 4 kB/s (`results/bench.json`, deterministic seeds):

| Link | Delivered | Delivered twice | Corrupted delivered | Retransmissions | Bad frames rejected |
|---|---|---|---|---|---|
| Clean | 2000/2000 | 0 | 0 | 1 | 0 |
| 10% loss | 2000/2000 | 0 | 0 | 297 | 0 |
| 30% loss, 5% duplication, 2% bit corruption | 2000/2000 | 0 | 0 | 2,494 | 107 |
| Same, authenticated (HMAC-SHA256) | 2000/2000 | 0 | 0 | 1,958 | 89 |

**Precedence under congestion.** A 1,500-message ROUTINE backlog (about 45 s of link time) with a FLASH message
every 2 s on top, 10% loss:

| | FLASH latency p50 | FLASH latency p99 |
|---|---|---|
| Precedence queues | 101 ms | **2.1 s** |
| First-in, first-out (ablation) | 284 ms | **49.7 s** |

**Real network, hostile path.** `tests/udp_loopback.rs` runs two authenticated endpoints over UDP on localhost through
a proxy that drops 20%, corrupts 2% and duplicates 3% of datagrams, and injects forged FLASH frames (correct format
and CRC, no key). All 1,000 messages arrive exactly once and intact; no forged frame is ever delivered.

Notes: the one retransmission on the clean link is spurious, sent before the timer had learned the jittery round-trip
time. At 30% loss, retransmissions push the 64 kbit/s link past capacity, so messages queue for tens of seconds while
still all arriving. Authentication adds 12 bytes per frame (16-byte tag instead of a 4-byte CRC); the goodput
difference between the two contested runs is run-to-run noise from different loss patterns, not a speedup.

## Security model

Without a key, a CRC-32C detects accidental corruption only: anyone who can send packets could inject messages or
acknowledge frames that never arrived. With a pre-shared 256-bit link key (`Config::key`):

- **Authentication:** every frame carries an HMAC-SHA256 tag (truncated to 128 bits) over the whole frame,
  verified in constant time before any field is read or any state changes (RustCrypto `hmac` and `sha2`).
- **Anti-replay:** each endpoint stamps its data frames with a timestamp-ordered session id. A receiver locks onto
  its peer's session and switches only to a *newer* session's first frame (a peer restart), so frames recorded from
  any earlier session are refused. Within a session, duplicates are suppressed.
- **Bound to direction:** acks carry the session they acknowledge, so an ack can only confirm the frames it was
  written for, and an endpoint rejects any frame bearing its own session id, which stops an attacker from
  reflecting a node's traffic back at it.
- **Bounded state:** data frames must fall inside `[base, base + 64)`; acks for frames never sent are ignored. A
  hostile sender cannot grow receiver memory or cancel retransmissions.

Out of scope: key exchange and rotation (keys are provisioned out of band), confidentiality (payloads are
authenticated, not encrypted), and denial of service by jamming. Anti-replay state lives in memory, so a receiver
that has just restarted will accept the first old session it hears; closing that gap needs a nonce handshake or
persisted state, which is the next step. Session ordering also relies on each node's clock (GPS time on a tactical
radio); a clock that steps backwards fails closed, with the peer refusing the restarted node until its clock catches up. The
session-id layout is part of the frame version, so frames from an older layout are rejected outright; in a fielded
system a format change would also come with a key rotation.

## Design

```
application ──send(msg, precedence)──▶ Endpoint (sans-IO state machine) ──poll_transmit(now)──▶ bytes
                                         ▲ handle(bytes, now)   │ poll_delivered()
                     ┌───────────────────┴──────────────┐       ▼
                     │ sim.rs: discrete-event link       │   application
                     │ udp.rs: UDP socket + I/O thread   │
                     └───────────────────────────────────┘
```

- **Frame** (`frame.rs`): magic, version, kind, precedence, session, sequence, cumulative ack, 32-bit selective ack,
  length, payload ≤ 1024 bytes, then CRC-32C or the HMAC tag. Tests flip every single bit of a frame (all rejected,
  with and without a key) and feed 200,000 random and mutated inputs (no panics).
- **Selective-repeat ARQ** (`endpoint.rs`): up to 32 frames in flight; acks carry the next expected sequence number
  plus a bitmap of the 32 after it, so only missing frames are resent.
- **Retransmission timer:** RFC 6298 smoothed RTT and variance, RTO = SRTT + 4·RTTVAR within [200 ms, 8 s], Karn's
  rule, exponential backoff per frame, and a failure report after 12 attempts.
- **Precedence:** four queues; whenever the link frees up, the highest-precedence new or due frame goes next.
  Messages are independent, so each is delivered as soon as it arrives instead of waiting behind a lost frame.
- **Concurrency** (`udp.rs`): one I/O thread per link owns the socket and the state machine; the application talks to
  it through channels, so no locks guard protocol state.
- **Determinism:** virtual clock and seeded SplitMix64 PRNG. Writing the simulator surfaced a real bug: wake-up
  events were rescheduled without de-duplication and multiplied exponentially; scheduled times are now tracked.

## Build and run

```bash
cargo test --release                       # 23 unit tests + the hostile-path UDP test
cargo run --release --bin linkd-bench      # scenarios above → results/bench.json
cargo clippy --all-targets -- -D warnings  # unsafe forbidden, unwrap() denied
```

## Limitations

- No congestion control beyond the fixed window; a production link would adapt to measured loss.
- Sequence numbers do not wrap within a session (4 billion frames).
- Unordered delivery by design; applications needing order would add it per message stream.
- Simulated radio physics are simple (independent loss, uniform jitter); real links have bursty loss.

## License and AI disclosure

MIT (see `LICENSE`). Built with help from Claude (Anthropic) via Claude Code; I reviewed, tested and verified the
code and results.
