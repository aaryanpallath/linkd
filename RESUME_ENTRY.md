# linkd — Reliable Messaging for Lossy Tactical Links (Rust)
Tech: Rust, UDP, multi-threading, HMAC-SHA256, Linux, Git, GitHub Actions
- Built a reliable messaging layer in Rust with selective-repeat ARQ, an RFC 6298 retransmission timer and FLASH/IMMEDIATE/PRIORITY/ROUTINE precedence, as a sans-IO state machine run by a simulator and a multi-threaded UDP runtime.
- Delivered 2,000 of 2,000 messages exactly once and intact over a simulated link with 30% loss, duplication and bit corruption; precedence cut FLASH p99 latency under congestion from 49.7 s to 2.1 s.
- Secured frames with HMAC-SHA256 authentication, session-based replay protection and bounded receive windows; parsing rejects every single-bit flip and survived 200,000 fuzzed inputs, with unsafe code forbidden.
