//! Deterministic discrete-event simulation of two endpoints over a lossy, bandwidth-limited link.
//!
//! Each message carries its id and a payload pattern derived from it, so the simulator can verify that every
//! message arrived exactly once and intact, and measure end-to-end latency per precedence.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use crate::endpoint::{Config, Endpoint};
use crate::frame::Precedence;
use crate::rng::Rng;

#[derive(Clone, Debug)]
pub struct LinkParams {
    pub delay_ms: u64,
    pub jitter_ms: u64,
    pub loss: f64,
    pub duplicate: f64,
    pub corrupt: f64,
    /// Link rate in bytes per millisecond (8 = 64 kbit/s).
    pub bytes_per_ms: f64,
}

#[derive(Clone, Debug)]
pub struct Message {
    pub at_ms: u64,
    pub precedence: Precedence,
    pub size: usize,
}

#[derive(Clone, Debug, Default)]
pub struct PrecedenceStats {
    pub sent: u64,
    pub delivered: u64,
    pub latency_ms: Vec<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub messages: u64,
    pub delivered: u64,
    pub delivered_twice: u64,
    pub delivered_corrupted: u64,
    pub failed: u64,
    pub frames_on_wire: u64,
    pub frames_lost: u64,
    pub frames_corrupted: u64,
    pub frames_rejected: u64,
    pub retransmissions: u64,
    pub duplicates_suppressed: u64,
    pub finished_ms: u64,
    pub goodput_bytes_per_s: f64,
    pub by_precedence: BTreeMap<String, PrecedenceStats>,
}

fn payload(id: u32, size: usize) -> Vec<u8> {
    let mut p = id.to_be_bytes().to_vec();
    p.extend(
        (0..size.saturating_sub(4)).map(|i| (id as usize).wrapping_mul(31).wrapping_add(i) as u8),
    );
    p
}

fn intact(p: &[u8]) -> Option<u32> {
    if p.len() < 4 {
        return None;
    }
    let id = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
    (payload(id, p.len()) == p).then_some(id)
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Ev {
    Offer(usize),
    Arrive(usize, Vec<u8>), // to endpoint index
    Wake,
}

pub fn run(
    cfg: &Config,
    link: &LinkParams,
    messages: &[Message],
    seed: u64,
    limit_ms: u64,
) -> Report {
    let mut rng = Rng::new(seed);
    let mut ep = [Endpoint::new(cfg.clone()), Endpoint::new(cfg.clone())];
    let mut busy_until = [0u64; 2];
    let mut events: BinaryHeap<Reverse<(u64, u64, Ev)>> = BinaryHeap::new();
    let mut order = 0u64;
    let mut push = |events: &mut BinaryHeap<_>, t: u64, e: Ev| {
        order += 1;
        events.push(Reverse((t, order, e)));
    };
    for (i, m) in messages.iter().enumerate() {
        push(&mut events, m.at_ms, Ev::Offer(i));
    }
    let mut r = Report {
        messages: messages.len() as u64,
        ..Report::default()
    };
    let mut seen = vec![false; messages.len()];
    let mut payload_bytes = 0u64;
    let name = |p: Precedence| format!("{p:?}").to_uppercase();
    for p in Precedence::ALL {
        r.by_precedence.insert(name(p), PrecedenceStats::default());
    }
    for m in messages {
        if let Some(s) = r.by_precedence.get_mut(&name(m.precedence)) {
            s.sent += 1;
        }
    }

    // wake-ups already scheduled: never schedule the same instant twice, or wake events multiply
    let mut wakes: BTreeSet<u64> = BTreeSet::new();
    let mut now = 0;
    while let Some(Reverse((t, _, ev))) = events.pop() {
        if t > limit_ms {
            break;
        }
        now = t;
        match ev {
            Ev::Offer(i) => {
                let m = &messages[i];
                let _ = ep[0].send(payload(i as u32, m.size), m.precedence);
            }
            Ev::Arrive(to, bytes) => {
                let _ = ep[to].handle(&bytes, now);
            }
            Ev::Wake => {
                wakes.remove(&t);
            }
        }
        while let Some((p, bytes)) = ep[1].poll_delivered() {
            match intact(&bytes) {
                Some(id) if (id as usize) < messages.len() => {
                    if seen[id as usize] {
                        r.delivered_twice += 1;
                    } else {
                        seen[id as usize] = true;
                        r.delivered += 1;
                        payload_bytes += bytes.len() as u64;
                        if let Some(s) = r.by_precedence.get_mut(&name(p)) {
                            s.delivered += 1;
                            s.latency_ms.push(now - messages[id as usize].at_ms);
                        }
                    }
                }
                _ => r.delivered_corrupted += 1,
            }
        }
        r.failed += ep[0].take_failed().len() as u64;
        // transmit whatever each endpoint has, paced by the link rate
        for i in 0..2 {
            while busy_until[i] <= now {
                let Some(mut bytes) = ep[i].poll_transmit(now) else {
                    break;
                };
                r.frames_on_wire += 1;
                let ser = (bytes.len() as f64 / link.bytes_per_ms).ceil() as u64;
                busy_until[i] = now + ser.max(1);
                if rng.unit() < link.loss {
                    r.frames_lost += 1;
                    continue;
                }
                if rng.unit() < link.corrupt {
                    r.frames_corrupted += 1;
                    let bit = rng.below(bytes.len() as u32 * 8) as usize;
                    bytes[bit / 8] ^= 1 << (bit % 8);
                }
                let copies = if rng.unit() < link.duplicate { 2 } else { 1 };
                for _ in 0..copies {
                    let jitter = if link.jitter_ms > 0 {
                        rng.below(link.jitter_ms as u32 + 1) as u64
                    } else {
                        0
                    };
                    push(
                        &mut events,
                        busy_until[i] + link.delay_ms + jitter,
                        Ev::Arrive(1 - i, bytes.clone()),
                    );
                }
            }
            let mut wake_at = |t: u64| {
                if wakes.insert(t) {
                    push(&mut events, t, Ev::Wake);
                }
            };
            if busy_until[i] > now && !ep[i].is_idle() {
                wake_at(busy_until[i]);
            }
            if let Some(t) = ep[i].next_timeout() {
                wake_at(t.max(busy_until[i]).max(now + 1));
            }
        }
        if r.delivered + r.failed == r.messages && ep[0].is_idle() {
            break;
        }
    }
    r.finished_ms = now;
    r.frames_rejected = ep[0].stats.frames_rejected + ep[1].stats.frames_rejected;
    r.retransmissions = ep[0].stats.retransmissions;
    r.duplicates_suppressed = ep[1].stats.duplicates_suppressed;
    r.goodput_bytes_per_s = if now > 0 {
        payload_bytes as f64 * 1000.0 / now as f64
    } else {
        0.0
    };
    for s in r.by_precedence.values_mut() {
        s.latency_ms.sort_unstable();
    }
    r
}

pub fn percentile(sorted: &[u64], p: f64) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let i = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted
        .get(i.saturating_sub(1).min(sorted.len() - 1))
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn steady(n: usize, every_ms: u64, p: Precedence) -> Vec<Message> {
        (0..n)
            .map(|i| Message {
                at_ms: i as u64 * every_ms,
                precedence: p,
                size: 200,
            })
            .collect()
    }

    const RADIO: LinkParams = LinkParams {
        delay_ms: 60,
        jitter_ms: 40,
        loss: 0.0,
        duplicate: 0.0,
        corrupt: 0.0,
        bytes_per_ms: 8.0,
    };

    #[test]
    fn clean_link_delivers_everything_once() {
        let r = run(
            &Config::default(),
            &RADIO,
            &steady(300, 50, Precedence::Routine),
            1,
            600_000,
        );
        assert_eq!(
            (
                r.delivered,
                r.delivered_twice,
                r.delivered_corrupted,
                r.failed
            ),
            (300, 0, 0, 0)
        );
        assert_eq!(r.retransmissions, 0);
    }

    #[test]
    fn hostile_link_still_delivers_exactly_once_and_intact() {
        let link = LinkParams {
            loss: 0.3,
            duplicate: 0.05,
            corrupt: 0.02,
            ..RADIO
        };
        let r = run(
            &Config::default(),
            &link,
            &steady(500, 50, Precedence::Priority),
            7,
            3_600_000,
        );
        assert_eq!(r.delivered, 500, "{r:?}");
        assert_eq!(
            (r.delivered_twice, r.delivered_corrupted, r.failed),
            (0, 0, 0)
        );
        assert!(r.frames_corrupted > 0 && r.frames_rejected >= r.frames_corrupted);
        assert!(r.retransmissions > 0 && r.duplicates_suppressed > 0);
    }

    #[test]
    fn same_seed_same_result() {
        let link = LinkParams { loss: 0.2, ..RADIO };
        let a = run(
            &Config::default(),
            &link,
            &steady(100, 20, Precedence::Routine),
            3,
            600_000,
        );
        let b = run(
            &Config::default(),
            &link,
            &steady(100, 20, Precedence::Routine),
            3,
            600_000,
        );
        assert_eq!(
            (a.finished_ms, a.retransmissions),
            (b.finished_ms, b.retransmissions)
        );
    }
}
