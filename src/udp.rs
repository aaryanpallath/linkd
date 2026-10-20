//! The endpoint over real UDP: one I/O thread per link, talking to the application through channels.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::endpoint::{Config, Endpoint, Stats};
use crate::frame::{MAX_FRAME, Precedence};

pub struct UdpLink {
    outbox: Sender<(Vec<u8>, Precedence)>,
    inbox: Receiver<(Precedence, Vec<u8>)>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Stats>>,
}

impl UdpLink {
    /// Bind `local`, exchange frames with `peer`, and run the protocol on a background thread.
    pub fn spawn(local: SocketAddr, peer: SocketAddr, cfg: Config) -> io::Result<UdpLink> {
        let socket = UdpSocket::bind(local)?;
        socket.set_read_timeout(Some(Duration::from_millis(2)))?;
        let (outbox, app_out) = mpsc::channel::<(Vec<u8>, Precedence)>();
        let (app_in, inbox) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = thread::Builder::new()
            .name("linkd-io".into())
            .spawn(move || {
                let start = Instant::now();
                let now = || start.elapsed().as_millis() as u64;
                let mut ep = Endpoint::new(cfg);
                let mut buf = vec![0u8; MAX_FRAME + 1]; // +1 so an oversized datagram is detected, not silently truncated
                while !flag.load(Ordering::Relaxed) {
                    while let Ok((payload, precedence)) = app_out.try_recv() {
                        let _ = ep.send(payload, precedence);
                    }
                    while let Some(frame) = ep.poll_transmit(now()) {
                        let _ = socket.send_to(&frame, peer);
                    }
                    match socket.recv_from(&mut buf) {
                        Ok((n, from)) if from == peer => {
                            let _ = ep.handle(&buf[..n], now());
                        }
                        _ => {} // timeout, or a datagram from anyone else: ignored
                    }
                    while let Some(m) = ep.poll_delivered() {
                        if app_in.send(m).is_err() {
                            break;
                        }
                    }
                }
                ep.stats
            })?;
        Ok(UdpLink {
            outbox,
            inbox,
            stop,
            thread: Some(thread),
        })
    }

    pub fn send(&self, payload: Vec<u8>, precedence: Precedence) -> bool {
        self.outbox.send((payload, precedence)).is_ok()
    }

    pub fn recv_timeout(&self, t: Duration) -> Option<(Precedence, Vec<u8>)> {
        self.inbox.recv_timeout(t).ok()
    }

    /// Stop the I/O thread and return its statistics.
    pub fn shutdown(mut self) -> Option<Stats> {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().and_then(|t| t.join().ok())
    }
}
