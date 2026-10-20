//! Reliable, precedence-aware messaging over lossy tactical links.
//!
//! * [`frame`]: the wire format (bounds-checked, CRC-32C protected).
//! * [`endpoint`]: the protocol as a sans-IO state machine: selective-repeat ARQ with an RFC 6298 retransmission
//!   timer, precedence queues, and exactly-once delivery.
//! * [`sim`]: a deterministic discrete-event simulator of a lossy, bandwidth-limited link.
//! * [`udp`]: the same endpoint running over real UDP sockets on its own threads.

pub mod crc;
pub mod endpoint;
pub mod frame;
pub mod rng;
pub mod sim;
pub mod udp;
