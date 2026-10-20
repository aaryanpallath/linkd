//! The protocol as a sans-IO state machine. It never touches a socket or a clock: callers feed it received bytes and
//! the current time, and ask it what to transmit next. The same code runs in the simulator and over UDP.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::frame::{Frame, FrameError, Kind, LinkKey, MAX_PAYLOAD, Precedence};
use crate::rng::Rng;

/// Frames are accepted only with sequence numbers in [base, base + RECV_WINDOW), which bounds receiver state and
/// must exceed the largest sender window plus the 32-frame selective-ack span.
pub const RECV_WINDOW: u32 = 64;

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
    /// Pre-shared link key. With a key every frame is authenticated (HMAC-SHA256); without one, frames carry only a
    /// CRC, which detects accidental corruption but not a deliberate forgery.
    pub key: Option<LinkKey>,
    /// This endpoint's session id; `None` picks a fresh one. Ids must increase across restarts (they are
    /// timestamp-ordered), because a peer accepts only sessions newer than the one it has; they need not be secret.
    pub session: Option<u64>,
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
            key: None,
            session: None,
        }
    }
}

/// Milliseconds since the epoch in the high 40 bits, random low bits, and strictly increasing within a process.
fn fresh_session() -> u64 {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let random = Rng::new(nanos ^ (std::process::id() as u64) << 32).next_u64() & 0xFF_FFFF;
    let candidate = (nanos / 1_000_000) << 24 | random;
    let prev = LAST.fetch_max(candidate, Ordering::Relaxed);
    if candidate > prev {
        candidate
    } else {
        LAST.fetch_add(1, Ordering::Relaxed) + 1
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
    PayloadTooLarge(usize),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Rejected {
    Frame(FrameError),
    StaleSession,
    /// A frame carrying this endpoint's own session: our traffic reflected back at us.
    Reflected,
    OutsideWindow,
    AckBeyondSent,
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
    session: u64,
    next_seq: u32,
    queues: [VecDeque<(Precedence, Vec<u8>)>; 4],
    inflight: BTreeMap<u32, InFlight>,
    srtt: Option<f64>,
    rttvar: f64,
    rto: u64,
    peer_session: Option<u64>,
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
        let session = cfg.session.unwrap_or_else(fresh_session);
        Endpoint {
            cfg,
            session,
            next_seq: 0,
            queues: Default::default(),
            inflight: BTreeMap::new(),
            srtt: None,
            rttvar: 0.0,
            rto,
            peer_session: None,
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

    pub fn session(&self) -> u64 {
        self.session
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

    /// Process bytes received from the network. Corrupt, forged, replayed or out-of-window frames are counted and
    /// dropped before they can change any state.
    pub fn handle(&mut self, bytes: &[u8], now: u64) -> Result<(), Rejected> {
        let result = Frame::decode(bytes, self.cfg.key.as_ref())
            .map_err(Rejected::Frame)
            .and_then(|f| match f.kind {
                Kind::Data => self.accept_session(&f).and_then(|()| self.on_data(f)),
                Kind::Ack => self.on_ack(&f, now),
            });
        if result.is_err() {
            self.stats.frames_rejected += 1;
        }
        result
    }

    /// Lock onto the peer's session (data frames carry the sender's session). A new session is accepted only through
    /// a first frame (sequence number 0) of a session newer than the current one, as after a peer restart, so frames
    /// recorded from any earlier session cannot be replayed. Our own session coming back is a reflection.
    fn accept_session(&mut self, f: &Frame) -> Result<(), Rejected> {
        if f.session == self.session {
            return Err(Rejected::Reflected);
        }
        match self.peer_session {
            None => {
                self.peer_session = Some(f.session);
                Ok(())
            }
            Some(s) if s == f.session => Ok(()),
            Some(current) => {
                if f.seq != 0 || f.session < current {
                    return Err(Rejected::StaleSession);
                }
                self.peer_session = Some(f.session);
                self.recv_base = 0;
                self.recv_seen.clear();
                Ok(())
            }
        }
    }

    fn on_data(&mut self, f: Frame) -> Result<(), Rejected> {
        if f.seq >= self.recv_base.saturating_add(RECV_WINDOW) {
            return Err(Rejected::OutsideWindow); // no legitimate sender can be this far ahead
        }
        self.ack_pending = true; // acknowledge duplicates too: the earlier ack may have been lost
        if f.seq < self.recv_base || self.recv_seen.contains(&f.seq) {
            self.stats.duplicates_suppressed += 1;
            return Ok(());
        }
        self.recv_seen.insert(f.seq);
        while self.recv_seen.remove(&self.recv_base) {
            self.recv_base += 1;
        }
        self.stats.delivered += 1;
        self.delivered.push_back((f.precedence, f.payload));
        Ok(())
    }

    /// Acks carry the session they acknowledge, so an ack is only ever applied to this session's frames.
    fn on_ack(&mut self, f: &Frame, now: u64) -> Result<(), Rejected> {
        let (ack, sack) = (f.ack, f.sack);
        if f.session != self.session {
            return Err(Rejected::StaleSession);
        }
        if ack > self.next_seq {
            return Err(Rejected::AckBeyondSent); // acknowledges frames that were never sent
        }
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
        Ok(())
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

    fn encode(&self, f: &Frame) -> Option<Vec<u8>> {
        f.encode(self.cfg.key.as_ref()).ok()
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
            // ack_pending is only set by an accepted data frame, so the peer session is known
            let acked_session = self.peer_session.unwrap_or_default();
            return self.encode(&Frame::ack(acked_session, self.recv_base, sack));
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
                let frame = f.frame.clone();
                return self.encode(&frame);
            }
        }
        if (self.inflight.len() as u32) < self.cfg.window
            && let Some((precedence, payload)) =
                self.queues.iter_mut().find_map(VecDeque::pop_front)
        {
            let seq = self.next_seq;
            self.next_seq += 1;
            let frame = Frame::data(self.session, seq, precedence, payload);
            let bytes = self.encode(&frame);
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

    fn keyed(b: u8) -> Config {
        Config {
            key: Some(LinkKey::new([b; 32])),
            ..Config::default()
        }
    }

    fn tx(e: &mut Endpoint, now: u64) -> Result<Vec<u8>, Rejected> {
        e.poll_transmit(now)
            .ok_or(Rejected::Frame(FrameError::TooShort))
    }

    #[test]
    fn delivers_and_acknowledges() -> Result<(), Rejected> {
        let (mut a, mut b) = pair();
        assert_eq!(a.send(b"hello".to_vec(), Precedence::Routine), Ok(()));
        let data = tx(&mut a, 0)?;
        b.handle(&data, 50)?;
        assert_eq!(
            b.poll_delivered(),
            Some((Precedence::Routine, b"hello".to_vec()))
        );
        let ack = tx(&mut b, 50)?;
        a.handle(&ack, 100)?;
        assert!(a.is_idle());
        assert_eq!(a.rto_ms(), 300); // RFC 6298 first sample: 100 + 4 * 50, above the 200 ms floor
        Ok(())
    }

    #[test]
    fn flash_jumps_the_queue() -> Result<(), Rejected> {
        let (mut a, _) = pair();
        for i in 0..5u8 {
            let _ = a.send(vec![i], Precedence::Routine);
        }
        let _ = a.send(b"flash".to_vec(), Precedence::Flash);
        let first = Frame::decode(&tx(&mut a, 0)?, None).map_err(Rejected::Frame)?;
        assert_eq!(first.precedence, Precedence::Flash);
        Ok(())
    }

    #[test]
    fn lost_frames_are_retransmitted_after_the_timeout_and_duplicates_suppressed()
    -> Result<(), Rejected> {
        let (mut a, mut b) = pair();
        let _ = a.send(b"x".to_vec(), Precedence::Priority);
        let first = tx(&mut a, 0)?; // pretend this one is lost
        assert!(a.poll_transmit(500).is_none()); // not yet due (initial RTO 1000 ms)
        let again = tx(&mut a, 1000)?;
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

    // ------------------------------------------------------------------ security
    #[test]
    fn forged_frames_never_change_state_on_an_authenticated_link() -> Result<(), Rejected> {
        let (mut a, mut b) = (Endpoint::new(keyed(1)), Endpoint::new(keyed(1)));
        let _ = a.send(b"real".to_vec(), Precedence::Routine);
        b.handle(&tx(&mut a, 0)?, 10)?;
        // an attacker who knows the format and the session, but not the key
        let forged = Frame::data(a.session(), 1, Precedence::Flash, b"fake order".to_vec());
        let no_key = forged.encode(None).map_err(Rejected::Frame)?;
        let wrong_key = forged
            .encode(Some(&LinkKey::new([2; 32])))
            .map_err(Rejected::Frame)?;
        assert!(b.handle(&no_key, 20).is_err());
        assert!(b.handle(&wrong_key, 20).is_err());
        assert_eq!(b.stats.delivered, 1);
        assert_eq!(b.poll_delivered().map(|m| m.1), Some(b"real".to_vec()));
        assert!(b.poll_delivered().is_none());
        Ok(())
    }

    #[test]
    fn spoofed_ack_for_unsent_frames_is_ignored() -> Result<(), Rejected> {
        let mut a = Endpoint::new(Config::default());
        for i in 0..3u8 {
            let _ = a.send(vec![i], Precedence::Routine);
            let _ = tx(&mut a, 0)?;
        }
        let bogus = Frame::ack(a.session(), 1_000, 0)
            .encode(None)
            .map_err(Rejected::Frame)?;
        assert_eq!(a.handle(&bogus, 10), Err(Rejected::AckBeyondSent));
        assert!(!a.is_idle()); // the three frames are still awaiting acknowledgement
        Ok(())
    }

    #[test]
    fn frames_far_ahead_are_rejected_and_state_stays_bounded() -> Result<(), Rejected> {
        let mut b = Endpoint::new(Config::default());
        let s = 7;
        // after seq 0 is accepted the window is [1, 1 + RECV_WINDOW): the first sequence number outside it is 65
        for seq in [0, RECV_WINDOW + 1, 1_000_000, u32::MAX] {
            let bytes = Frame::data(s, seq, Precedence::Routine, vec![1])
                .encode(None)
                .map_err(Rejected::Frame)?;
            let r = b.handle(&bytes, 0);
            assert_eq!(r.is_ok(), seq == 0, "seq {seq}");
        }
        assert_eq!(b.stats.delivered, 1);
        Ok(())
    }

    #[test]
    fn frames_from_a_replaced_session_cannot_be_replayed() -> Result<(), Rejected> {
        let key = keyed(5);
        let mut b = Endpoint::new(key.clone());
        let mut old = Endpoint::new(Config {
            session: Some(1),
            ..key.clone()
        });
        let _ = old.send(b"old message".to_vec(), Precedence::Routine);
        let recorded = tx(&mut old, 0)?;
        b.handle(&recorded, 1)?;
        // the peer restarts with a new session; its first frame (seq 0) is accepted
        let mut new = Endpoint::new(Config {
            session: Some(2),
            ..key
        });
        let _ = new.send(b"new message".to_vec(), Precedence::Routine);
        b.handle(&tx(&mut new, 10)?, 11)?;
        // replaying the recorded frame from the old session is refused, even though its tag is valid
        assert_eq!(b.handle(&recorded, 20), Err(Rejected::StaleSession));
        let got: Vec<Vec<u8>> = std::iter::from_fn(|| b.poll_delivered().map(|m| m.1)).collect();
        assert_eq!(got, vec![b"old message".to_vec(), b"new message".to_vec()]);
        Ok(())
    }

    #[test]
    fn a_never_seen_but_older_session_cannot_take_over() -> Result<(), Rejected> {
        let key = keyed(5);
        let mut b = Endpoint::new(key.clone());
        let mut current = Endpoint::new(Config {
            session: Some(20),
            ..key.clone()
        });
        let _ = current.send(b"current".to_vec(), Precedence::Routine);
        b.handle(&tx(&mut current, 0)?, 1)?;
        // a validly tagged first frame recorded from an earlier session (e.g. a week-old capture)
        let mut earlier = Endpoint::new(Config {
            session: Some(10),
            ..key
        });
        let _ = earlier.send(b"replayed".to_vec(), Precedence::Flash);
        assert_eq!(
            b.handle(&tx(&mut earlier, 0)?, 2),
            Err(Rejected::StaleSession)
        );
        assert_eq!(b.stats.delivered, 1);
        Ok(())
    }

    #[test]
    fn reflected_frames_are_rejected() -> Result<(), Rejected> {
        let (mut a, mut b) = (Endpoint::new(keyed(3)), Endpoint::new(keyed(3)));
        let _ = a.send(b"order".to_vec(), Precedence::Flash);
        let data = tx(&mut a, 0)?;
        // an attacker bounces a's own data frame back to a: same key, valid tag
        assert_eq!(a.handle(&data, 5), Err(Rejected::Reflected));
        assert!(a.poll_delivered().is_none());
        // b's ack names a's session; reflected back to b it acknowledges nothing of b's
        b.handle(&data, 10)?;
        let ack = tx(&mut b, 10)?;
        assert_eq!(b.handle(&ack, 15), Err(Rejected::StaleSession));
        a.handle(&ack, 20)?;
        assert!(a.is_idle());
        Ok(())
    }

    #[test]
    fn acks_for_another_session_are_ignored() -> Result<(), Rejected> {
        let mut a = Endpoint::new(keyed(4));
        let _ = a.send(b"x".to_vec(), Precedence::Routine);
        let _ = tx(&mut a, 0)?;
        let other = Frame::ack(a.session() ^ 1, 1, 0)
            .encode(Some(&LinkKey::new([4; 32])))
            .map_err(Rejected::Frame)?;
        assert_eq!(a.handle(&other, 10), Err(Rejected::StaleSession));
        assert!(!a.is_idle());
        Ok(())
    }

    #[test]
    fn fresh_sessions_strictly_increase() {
        let ids: Vec<u64> = (0..1000).map(|_| fresh_session()).collect();
        assert!(ids.windows(2).all(|w| w[0] < w[1]));
    }
}
