//! The protocol as a sans-IO state machine. It never touches a socket or a clock: callers feed it received bytes and
//! the current time, and ask it what to transmit next. The same code runs in the simulator and over UDP.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::frame::{Frame, FrameError, Kind, MAX_PAYLOAD, Precedence};

#[derive(Clone, Debug)]
pub struct Config {
    /// Maximum unacknowledged frames in flight (at most 33, so the 32-bit selective ack covers the window).
    pub window: u32,
    pub rto_initial_ms: u64,
    pub rto_min_ms: u64,
    pub rto_max_ms: u64,
    /// Transmissions per frame before it is reported as failed.
    pub max_attempts: u32,
    /// Ablation switch: ignore precedence and send strictly first-in, first-out.
    pub fifo: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            window: 32,
            rto_initial_ms: 1000,
            rto_min_ms: 200,
            rto_max_ms: 8000,
            max_attempts: 12,
            fifo: false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
    PayloadTooLarge(usize),
}

#[derive(Default, Clone, Debug)]
pub struct Stats {
    pub data_sent: u64,
    pub retransmissions: u64,
    pub acks_sent: u64,
    pub delivered: u64,
    pub duplicates_suppressed: u64,
    pub frames_rejected: u64,
    pub failed: u64,
}

struct InFlight {
    frame: Frame,
    first_sent: u64,
    last_sent: u64,
    attempts: u32,
}

pub struct Endpoint {
    cfg: Config,
    next_seq: u32,
    queues: [VecDeque<(Precedence, Vec<u8>)>; 4],
    inflight: BTreeMap<u32, InFlight>,
    srtt: Option<f64>,
    rttvar: f64,
    rto: u64,
    recv_base: u32,
    recv_seen: BTreeSet<u32>,
    ack_pending: bool,
    delivered: VecDeque<(Precedence, Vec<u8>)>,
    failed: Vec<(Precedence, Vec<u8>)>,
    pub stats: Stats,
}

impl Endpoint {
    pub fn new(cfg: Config) -> Self {
        let rto = cfg.rto_initial_ms;
        Endpoint {
            cfg,
            next_seq: 0,
            queues: Default::default(),
            inflight: BTreeMap::new(),
            srtt: None,
            rttvar: 0.0,
            rto,
            recv_base: 0,
            recv_seen: BTreeSet::new(),
            ack_pending: false,
            delivered: VecDeque::new(),
            failed: Vec::new(),
            stats: Stats::default(),
        }
    }

    pub fn rto_ms(&self) -> u64 {
        self.rto
    }

    /// Queue a message. FLASH traffic is transmitted before any lower precedence (unless `fifo` is set).
    pub fn send(&mut self, payload: Vec<u8>, precedence: Precedence) -> Result<(), SendError> {
        if payload.len() > MAX_PAYLOAD {
            return Err(SendError::PayloadTooLarge(payload.len()));
        }
        let q = if self.cfg.fifo {
            0
        } else {
            precedence as usize
        };
        self.queues[q].push_back((precedence, payload));
        Ok(())
    }

    /// Messages received from the peer, each exactly once, in arrival order.
    pub fn poll_delivered(&mut self) -> Option<(Precedence, Vec<u8>)> {
        self.delivered.pop_front()
    }

    /// Messages given up on after `max_attempts` transmissions.
    pub fn take_failed(&mut self) -> Vec<(Precedence, Vec<u8>)> {
        std::mem::take(&mut self.failed)
    }

    pub fn is_idle(&self) -> bool {
        self.inflight.is_empty() && self.queues.iter().all(VecDeque::is_empty) && !self.ack_pending
    }

    /// Process bytes received from the network. Corrupt or malformed frames are counted and dropped.
    pub fn handle(&mut self, bytes: &[u8], now: u64) -> Result<(), FrameError> {
        let frame = match Frame::decode(bytes) {
            Ok(f) => f,
            Err(e) => {
                self.stats.frames_rejected += 1;
                return Err(e);
            }
        };
        match frame.kind {
            Kind::Data => self.on_data(frame),
            Kind::Ack => self.on_ack(frame.ack, frame.sack, now),
        }
        Ok(())
    }

    fn on_data(&mut self, f: Frame) {
        self.ack_pending = true; // always acknowledge, even duplicates: the earlier ack may have been lost
        if f.seq < self.recv_base || self.recv_seen.contains(&f.seq) {
            self.stats.duplicates_suppressed += 1;
            return;
        }
        self.recv_seen.insert(f.seq);
        while self.recv_seen.remove(&self.recv_base) {
            self.recv_base += 1;
        }
        self.stats.delivered += 1;
        self.delivered.push_back((f.precedence, f.payload));
    }

    fn on_ack(&mut self, ack: u32, sack: u32, now: u64) {
        let mut acked: Vec<u32> = self.inflight.range(..ack).map(|(s, _)| *s).collect();
        for i in 0..32u32 {
            if sack & (1 << i) != 0 {
                acked.push(ack.wrapping_add(1 + i));
            }
        }
        for seq in acked {
            // Karn's algorithm: only frames sent once give an unambiguous round-trip sample
            if let Some(f) = self.inflight.remove(&seq)
                && f.attempts == 1
            {
                self.rtt_sample(now.saturating_sub(f.first_sent) as f64);
            }
        }
    }

    /// RFC 6298 estimator: SRTT, RTTVAR, RTO = SRTT + 4 * RTTVAR, clamped.
    fn rtt_sample(&mut self, r: f64) {
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2.0;
            }
            Some(s) => {
                self.rttvar = 0.75 * self.rttvar + 0.25 * (s - r).abs();
                self.srtt = Some(0.875 * s + 0.125 * r);
            }
        }
        let rto = self.srtt.unwrap_or(r) + (4.0 * self.rttvar).max(1.0);
        self.rto = (rto.ceil() as u64).clamp(self.cfg.rto_min_ms, self.cfg.rto_max_ms);
    }

    fn deadline(&self, f: &InFlight) -> u64 {
        let backoff = self.rto.saturating_mul(1 << (f.attempts - 1).min(6));
        f.last_sent + backoff.min(self.cfg.rto_max_ms)
    }

    /// Earliest time this endpoint needs to be woken for a retransmission.
    pub fn next_timeout(&self) -> Option<u64> {
        self.inflight.values().map(|f| self.deadline(f)).min()
    }

    /// The next frame to put on the wire, if any: acks first, then due retransmissions and new data, each by
    /// precedence. Callers pace calls to the link rate.
    pub fn poll_transmit(&mut self, now: u64) -> Option<Vec<u8>> {
        if self.ack_pending {
            self.ack_pending = false;
            self.stats.acks_sent += 1;
            let mut sack = 0u32;
            for i in 0..32u32 {
                if self.recv_seen.contains(&self.recv_base.wrapping_add(1 + i)) {
                    sack |= 1 << i;
                }
            }
            return Frame::ack(self.recv_base, sack).encode().ok();
        }
        // due retransmissions, highest precedence first; frames out of attempts are reported as failed
        loop {
            let due = self
                .inflight
                .iter()
                .filter(|(_, f)| self.deadline(f) <= now)
                .min_by_key(|(seq, f)| {
                    (
                        if self.cfg.fifo {
                            0
                        } else {
                            f.frame.precedence as u8
                        },
                        **seq,
                    )
                })
                .map(|(seq, _)| *seq);
            let Some(seq) = due else { break };
            let at_limit = self
                .inflight
                .get(&seq)
                .is_some_and(|f| f.attempts >= self.cfg.max_attempts);
            if at_limit {
                if let Some(f) = self.inflight.remove(&seq) {
                    self.stats.failed += 1;
                    self.failed.push((f.frame.precedence, f.frame.payload));
                }
                continue;
            }
            if let Some(f) = self.inflight.get_mut(&seq) {
                f.attempts += 1;
                f.last_sent = now;
                self.stats.retransmissions += 1;
                return f.frame.encode().ok();
            }
        }
        if (self.inflight.len() as u32) < self.cfg.window
            && let Some((precedence, payload)) =
                self.queues.iter_mut().find_map(VecDeque::pop_front)
        {
            let seq = self.next_seq;
            self.next_seq += 1;
            let frame = Frame::data(seq, precedence, payload);
            let bytes = frame.encode().ok();
            self.inflight.insert(
                seq,
                InFlight {
                    frame,
                    first_sent: now,
                    last_sent: now,
                    attempts: 1,
                },
            );
            self.stats.data_sent += 1;
            return bytes;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Endpoint, Endpoint) {
        (
            Endpoint::new(Config::default()),
            Endpoint::new(Config::default()),
        )
    }

    #[test]
    fn delivers_and_acknowledges() -> Result<(), FrameError> {
        let (mut a, mut b) = pair();
        assert_eq!(a.send(b"hello".to_vec(), Precedence::Routine), Ok(()));
        let data = a.poll_transmit(0).ok_or(FrameError::TooShort)?;
        b.handle(&data, 50)?;
        assert_eq!(
            b.poll_delivered(),
            Some((Precedence::Routine, b"hello".to_vec()))
        );
        let ack = b.poll_transmit(50).ok_or(FrameError::TooShort)?;
        a.handle(&ack, 100)?;
        assert!(a.is_idle());
        assert_eq!(a.rto_ms(), 300); // RFC 6298 first sample: 100 + 4 * 50, above the 200 ms floor
        Ok(())
    }

    #[test]
    fn flash_jumps_the_queue() -> Result<(), FrameError> {
        let (mut a, _) = pair();
        for i in 0..5u8 {
            let _ = a.send(vec![i], Precedence::Routine);
        }
        let _ = a.send(b"flash".to_vec(), Precedence::Flash);
        let first = Frame::decode(&a.poll_transmit(0).ok_or(FrameError::TooShort)?)?;
        assert_eq!(first.precedence, Precedence::Flash);
        Ok(())
    }

    #[test]
    fn lost_frames_are_retransmitted_after_the_timeout_and_duplicates_suppressed()
    -> Result<(), FrameError> {
        let (mut a, mut b) = pair();
        let _ = a.send(b"x".to_vec(), Precedence::Priority);
        let first = a.poll_transmit(0).ok_or(FrameError::TooShort)?; // pretend this one is lost
        assert!(a.poll_transmit(500).is_none()); // not yet due (initial RTO 1000 ms)
        let again = a.poll_transmit(1000).ok_or(FrameError::TooShort)?;
        assert_eq!(a.stats.retransmissions, 1);
        b.handle(&again, 1050)?;
        b.handle(&first, 1060)?; // the "lost" copy arrives late
        assert_eq!(b.stats.delivered, 1);
        assert_eq!(b.stats.duplicates_suppressed, 1);
        Ok(())
    }

    #[test]
    fn gives_up_after_max_attempts() {
        let mut a = Endpoint::new(Config {
            max_attempts: 3,
            ..Config::default()
        });
        let _ = a.send(b"x".to_vec(), Precedence::Routine);
        let mut t = 0;
        for _ in 0..10 {
            let _ = a.poll_transmit(t);
            t += 10_000;
        }
        assert_eq!(a.take_failed().len(), 1);
        assert!(a.is_idle());
    }

    #[test]
    fn window_limits_frames_in_flight() {
        let mut a = Endpoint::new(Config {
            window: 4,
            ..Config::default()
        });
        for i in 0..10u8 {
            let _ = a.send(vec![i], Precedence::Routine);
        }
        let sent = (0..10).filter_map(|_| a.poll_transmit(0)).count();
        assert_eq!(sent, 4);
    }

    #[test]
    fn oversized_messages_are_refused() {
        let mut a = Endpoint::new(Config::default());
        assert_eq!(
            a.send(vec![0; MAX_PAYLOAD + 1], Precedence::Routine),
            Err(SendError::PayloadTooLarge(MAX_PAYLOAD + 1))
        );
    }
}
