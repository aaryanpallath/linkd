# linkd — Reliable Messaging for Lossy Tactical Links (Rust)
Tech: Rust, UDP, multi-threading, Linux, Git, GitHub Actions
- Built a reliable messaging layer in Rust with a CRC-32C frame format, selective-repeat ARQ, an RFC 6298 retransmission timer and FLASH/IMMEDIATE/PRIORITY/ROUTINE precedence, as a sans-IO state machine run by a simulator and a multi-threaded UDP runtime.
- Delivered 2,000 of 2,000 messages exactly once and intact over a simulated link with 30% loss, duplication and bit corruption; precedence cut FLASH p99 latency under congestion from 47.8 s to 0.86 s.
- Hardened frame parsing against malformed input (every single-bit flip rejected, 200,000 fuzzed inputs without a panic), with unsafe code forbidden and Clippy warnings as errors in CI.
