//! Two endpoints over real UDP on localhost, through an impairment proxy that drops, corrupts and duplicates.

use std::collections::HashSet;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use linkd::endpoint::Config;
use linkd::frame::Precedence;
use linkd::rng::Rng;
use linkd::udp::UdpLink;

fn free_addr() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap_or_else(|_| unreachable!()))
}

/// Forward datagrams between a and b, dropping 20%, corrupting 2% and duplicating 3% of them.
fn proxy(
    listen_a: SocketAddr,
    listen_b: SocketAddr,
    a: SocketAddr,
    b: SocketAddr,
    stop: Arc<AtomicBool>,
) {
    let sa = UdpSocket::bind(listen_a).unwrap_or_else(|e| panic!("bind {e}"));
    let sb = UdpSocket::bind(listen_b).unwrap_or_else(|e| panic!("bind {e}"));
    for s in [&sa, &sb] {
        let _ = s.set_read_timeout(Some(Duration::from_millis(1)));
    }
    let mut rng = Rng::new(99);
    let mut buf = [0u8; 2048];
    while !stop.load(Ordering::Relaxed) {
        for (from_sock, to_sock, to) in [(&sa, &sb, b), (&sb, &sa, a)] {
            if let Ok((n, _)) = from_sock.recv_from(&mut buf) {
                if rng.unit() < 0.20 {
                    continue;
                }
                let mut d = buf[..n].to_vec();
                if rng.unit() < 0.02 {
                    let bit = rng.below(n as u32 * 8) as usize;
                    d[bit / 8] ^= 1 << (bit % 8);
                }
                let copies = if rng.unit() < 0.03 { 2 } else { 1 };
                for _ in 0..copies {
                    let _ = to_sock.send_to(&d, to);
                }
            }
        }
    }
}

#[test]
fn messages_cross_a_lossy_udp_link_exactly_once_and_intact() {
    let (a, b, pa, pb) = (free_addr(), free_addr(), free_addr(), free_addr());
    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let px = thread::spawn(move || proxy(pa, pb, a, b, s2));
    let cfg = Config {
        rto_initial_ms: 50,
        rto_min_ms: 20,
        ..Config::default()
    };
    let left = UdpLink::spawn(a, pa, cfg.clone()).unwrap_or_else(|e| panic!("{e}"));
    let right = UdpLink::spawn(b, pb, cfg).unwrap_or_else(|e| panic!("{e}"));

    let n = 1000u32;
    for i in 0..n {
        let p = if i % 10 == 0 {
            Precedence::Flash
        } else {
            Precedence::Routine
        };
        let mut payload = i.to_be_bytes().to_vec();
        payload.extend(std::iter::repeat_n((i % 251) as u8, 96));
        assert!(left.send(payload, p));
    }
    let mut got = HashSet::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    while got.len() < n as usize && Instant::now() < deadline {
        if let Some((_, p)) = right.recv_timeout(Duration::from_millis(50)) {
            let id = u32::from_be_bytes([p[0], p[1], p[2], p[3]]);
            assert!(
                p[4..].iter().all(|&x| x == (id % 251) as u8),
                "corrupted payload delivered"
            );
            assert!(got.insert(id), "message {id} delivered twice");
        }
    }
    stop.store(true, Ordering::Relaxed);
    let stats = left.shutdown();
    let rstats = right.shutdown();
    let _ = px.join();
    assert_eq!(got.len(), n as usize);
    assert!(stats.is_some_and(|s| s.retransmissions > 0));
    assert!(rstats.is_some_and(|s| s.frames_rejected + s.duplicates_suppressed > 0));
}
