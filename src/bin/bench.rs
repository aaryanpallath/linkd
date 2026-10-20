//! Benchmark scenarios on the simulated link; writes results/bench.json and prints a summary table.

use std::fmt::Write as _;

use linkd::endpoint::Config;
use linkd::frame::Precedence;
use linkd::sim::{LinkParams, Message, Report, percentile, run};

const RADIO: LinkParams = LinkParams {
    delay_ms: 60,
    jitter_ms: 40,
    loss: 0.0,
    duplicate: 0.0,
    corrupt: 0.0,
    bytes_per_ms: 8.0,
};

fn steady(n: usize, every_ms: u64) -> Vec<Message> {
    (0..n)
        .map(|i| Message {
            at_ms: i as u64 * every_ms,
            precedence: Precedence::Routine,
            size: 200,
        })
        .collect()
}

/// A burst of 1,500 routine messages (several minutes of link time) with a FLASH message every 2 s on top.
fn congested() -> Vec<Message> {
    let mut m: Vec<Message> = (0..1500)
        .map(|_| Message {
            at_ms: 0,
            precedence: Precedence::Routine,
            size: 200,
        })
        .collect();
    m.extend((0..60).map(|i| Message {
        at_ms: 500 + i * 2000,
        precedence: Precedence::Flash,
        size: 64,
    }));
    m
}

fn json(name: &str, r: &Report, extra: &str) -> String {
    let mut by = String::new();
    for (k, s) in &r.by_precedence {
        if s.sent == 0 {
            continue;
        }
        let _ = write!(
            by,
            "{}\"{}\": {{\"sent\": {}, \"delivered\": {}, \"p50_ms\": {}, \"p99_ms\": {}}}",
            if by.is_empty() { "" } else { ", " },
            k,
            s.sent,
            s.delivered,
            percentile(&s.latency_ms, 50.0).unwrap_or(0),
            percentile(&s.latency_ms, 99.0).unwrap_or(0)
        );
    }
    format!(
        "  \"{name}\": {{{extra}\"messages\": {}, \"delivered\": {}, \"delivered_twice\": {}, \
             \"delivered_corrupted\": {}, \"failed\": {}, \"frames_on_wire\": {}, \"frames_lost\": {}, \
             \"frames_corrupted\": {}, \"frames_rejected\": {}, \"retransmissions\": {}, \
             \"duplicates_suppressed\": {}, \"finished_ms\": {}, \"goodput_bytes_per_s\": {:.1}, \
             \"by_precedence\": {{{by}}}}}",
        r.messages,
        r.delivered,
        r.delivered_twice,
        r.delivered_corrupted,
        r.failed,
        r.frames_on_wire,
        r.frames_lost,
        r.frames_corrupted,
        r.frames_rejected,
        r.retransmissions,
        r.duplicates_suppressed,
        r.finished_ms,
        r.goodput_bytes_per_s
    )
}

fn main() {
    let cfg = Config::default();
    let fifo = Config {
        fifo: true,
        ..Config::default()
    };
    let mut out = Vec::new();
    println!(
        "{:<34} {:>9} {:>6} {:>6} {:>8} {:>9} {:>11}",
        "scenario", "delivered", "twice", "bad", "retrans", "rejected", "goodput B/s"
    );
    for (name, link) in [
        ("clean", RADIO.clone()),
        (
            "loss_10pct",
            LinkParams {
                loss: 0.10,
                ..RADIO.clone()
            },
        ),
        (
            "contested_30pct_loss",
            LinkParams {
                loss: 0.30,
                duplicate: 0.05,
                corrupt: 0.02,
                ..RADIO.clone()
            },
        ),
    ] {
        let r = run(&cfg, &link, &steady(2000, 50), 2026, 7_200_000);
        println!(
            "{:<34} {:>9} {:>6} {:>6} {:>8} {:>9} {:>11.0}",
            name,
            format!("{}/{}", r.delivered, r.messages),
            r.delivered_twice,
            r.delivered_corrupted,
            r.retransmissions,
            r.frames_rejected,
            r.goodput_bytes_per_s
        );
        out.push(json(name, &r, ""));
    }
    let link = LinkParams {
        loss: 0.10,
        ..RADIO.clone()
    };
    for (name, c) in [
        ("congested_with_precedence", &cfg),
        ("congested_fifo_ablation", &fifo),
    ] {
        let r = run(c, &link, &congested(), 2027, 7_200_000);
        let f = &r.by_precedence["FLASH"].latency_ms;
        let rt = &r.by_precedence["ROUTINE"].latency_ms;
        println!(
            "{:<34} FLASH p50 {:>6} ms p99 {:>6} ms | ROUTINE p50 {:>6} ms | delivered {}/{}",
            name,
            percentile(f, 50.0).unwrap_or(0),
            percentile(f, 99.0).unwrap_or(0),
            percentile(rt, 50.0).unwrap_or(0),
            r.delivered,
            r.messages
        );
        out.push(json(name, &r, ""));
    }
    let body = format!("{{\n{}\n}}\n", out.join(",\n"));
    let _ = std::fs::create_dir_all("results");
    if std::fs::write("results/bench.json", body).is_ok() {
        println!("wrote results/bench.json");
    }
}
