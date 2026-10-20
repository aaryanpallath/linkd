//! Wire format. Every field is bounds-checked on decode; malformed input returns an error, never panics.
//!
//! ```text
//! 0      2   3    4           5         13    17    21     25    27          27+len
//! | "LK" |ver|kind| precedence| session | seq | ack | sack | len | payload | trailer |
//! ```
//! The trailer is a CRC-32C (4 bytes) on an unauthenticated link, or a truncated HMAC-SHA256 tag (16 bytes) over
//! everything before it when the link has a pre-shared key. The trailer is verified before any field is trusted.
//! `session` identifies the sender's session (anti-replay across restarts); `ack` is the next sequence number the
//! receiver expects and `sack` marks which of the 32 after it have also arrived (selective acknowledgement).

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::crc::crc32c;

pub const MAGIC: [u8; 2] = *b"LK";
pub const VERSION: u8 = 2;
pub const HEADER_LEN: usize = 27;
pub const MAX_PAYLOAD: usize = 1024;
pub const CRC_LEN: usize = 4;
pub const TAG_LEN: usize = 16;
pub const MAX_FRAME: usize = HEADER_LEN + MAX_PAYLOAD + TAG_LEN;

/// A pre-shared 256-bit link key. With a key, frames are authenticated with HMAC-SHA256 (truncated to 128 bits).
#[derive(Clone)]
pub struct LinkKey([u8; 32]);

impl LinkKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        LinkKey(bytes)
    }

    fn mac(&self) -> Hmac<Sha256> {
        // HMAC accepts keys of any length, so construction cannot fail for a 32-byte key
        <Hmac<Sha256> as KeyInit>::new_from_slice(&self.0).unwrap_or_else(|_| unreachable!())
    }
}

impl std::fmt::Debug for LinkKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LinkKey(<redacted>)")
    }
}

/// Message precedence, highest first (after the military FLASH / IMMEDIATE / PRIORITY / ROUTINE levels).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Precedence {
    Flash = 0,
    Immediate = 1,
    Priority = 2,
    Routine = 3,
}

impl Precedence {
    pub const ALL: [Precedence; 4] = [Self::Flash, Self::Immediate, Self::Priority, Self::Routine];

    fn from_u8(v: u8) -> Option<Self> {
        Self::ALL.get(v as usize).copied()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Data = 1,
    Ack = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: Kind,
    pub precedence: Precedence,
    pub session: u64,
    pub seq: u32,
    pub ack: u32,
    pub sack: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    TooShort,
    BadMagic,
    BadVersion(u8),
    BadKind(u8),
    BadPrecedence(u8),
    PayloadTooLarge(usize),
    LengthMismatch,
    BadChecksum,
    BadAuthTag,
}

impl Frame {
    pub fn data(session: u64, seq: u32, precedence: Precedence, payload: Vec<u8>) -> Self {
        Frame {
            kind: Kind::Data,
            precedence,
            session,
            seq,
            ack: 0,
            sack: 0,
            payload,
        }
    }

    pub fn ack(session: u64, ack: u32, sack: u32) -> Self {
        Frame {
            kind: Kind::Ack,
            precedence: Precedence::Flash,
            session,
            seq: 0,
            ack,
            sack,
            payload: Vec::new(),
        }
    }

    pub fn encode(&self, key: Option<&LinkKey>) -> Result<Vec<u8>, FrameError> {
        if self.payload.len() > MAX_PAYLOAD {
            return Err(FrameError::PayloadTooLarge(self.payload.len()));
        }
        let mut b = Vec::with_capacity(HEADER_LEN + self.payload.len() + TAG_LEN);
        b.extend_from_slice(&MAGIC);
        b.push(VERSION);
        b.push(self.kind as u8);
        b.push(self.precedence as u8);
        b.extend_from_slice(&self.session.to_be_bytes());
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.ack.to_be_bytes());
        b.extend_from_slice(&self.sack.to_be_bytes());
        b.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        b.extend_from_slice(&self.payload);
        match key {
            Some(k) => {
                let mut mac = k.mac();
                mac.update(&b);
                let tag = mac.finalize().into_bytes();
                b.extend_from_slice(&tag[..TAG_LEN]);
            }
            None => {
                let crc = crc32c(&b);
                b.extend_from_slice(&crc.to_be_bytes());
            }
        }
        Ok(b)
    }

    pub fn decode(b: &[u8], key: Option<&LinkKey>) -> Result<Frame, FrameError> {
        let trailer = if key.is_some() { TAG_LEN } else { CRC_LEN };
        if b.len() < HEADER_LEN + trailer {
            return Err(FrameError::TooShort);
        }
        // the trailer is checked first: nothing in a forged or corrupted frame is trusted
        let (body, t) = b.split_at(b.len() - trailer);
        match key {
            Some(k) => {
                let mut mac = k.mac();
                mac.update(body);
                mac.verify_truncated_left(t)
                    .map_err(|_| FrameError::BadAuthTag)?; // constant time
            }
            None => {
                if crc32c(body) != u32::from_be_bytes([t[0], t[1], t[2], t[3]]) {
                    return Err(FrameError::BadChecksum);
                }
            }
        }
        if body[0..2] != MAGIC {
            return Err(FrameError::BadMagic);
        }
        if body[2] != VERSION {
            return Err(FrameError::BadVersion(body[2]));
        }
        let kind = match body[3] {
            1 => Kind::Data,
            2 => Kind::Ack,
            k => return Err(FrameError::BadKind(k)),
        };
        let precedence = Precedence::from_u8(body[4]).ok_or(FrameError::BadPrecedence(body[4]))?;
        let u32_at =
            |i: usize| u32::from_be_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);
        let mut s = [0u8; 8];
        s.copy_from_slice(&body[5..13]);
        let len = u16::from_be_bytes([body[25], body[26]]) as usize;
        if len > MAX_PAYLOAD {
            return Err(FrameError::PayloadTooLarge(len));
        }
        if body.len() != HEADER_LEN + len {
            return Err(FrameError::LengthMismatch);
        }
        Ok(Frame {
            kind,
            precedence,
            session: u64::from_be_bytes(s),
            seq: u32_at(13),
            ack: u32_at(17),
            sack: u32_at(21),
            payload: body[HEADER_LEN..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;

    fn key(b: u8) -> LinkKey {
        LinkKey::new([b; 32])
    }

    #[test]
    fn round_trip_with_and_without_a_key() -> Result<(), FrameError> {
        let f = Frame::data(77, 42, Precedence::Immediate, b"position report".to_vec());
        assert_eq!(Frame::decode(&f.encode(None)?, None)?, f);
        assert_eq!(Frame::decode(&f.encode(Some(&key(1)))?, Some(&key(1)))?, f);
        let a = Frame::ack(78, 7, 0b1011);
        assert_eq!(Frame::decode(&a.encode(Some(&key(1)))?, Some(&key(1)))?, a);
        Ok(())
    }

    #[test]
    fn oversized_payload_is_refused() {
        assert_eq!(
            Frame::data(1, 1, Precedence::Routine, vec![0; MAX_PAYLOAD + 1]).encode(None),
            Err(FrameError::PayloadTooLarge(MAX_PAYLOAD + 1))
        );
    }

    #[test]
    fn every_single_bit_flip_is_detected() -> Result<(), FrameError> {
        for k in [None, Some(key(3))] {
            let bytes = Frame::data(5, 9, Precedence::Flash, b"contact bearing 270".to_vec())
                .encode(k.as_ref())?;
            for i in 0..bytes.len() * 8 {
                let mut m = bytes.clone();
                m[i / 8] ^= 1 << (i % 8);
                assert!(
                    Frame::decode(&m, k.as_ref()).is_err(),
                    "bit {i} flip accepted"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn forged_frames_are_rejected_on_an_authenticated_link() -> Result<(), FrameError> {
        let f = Frame::data(5, 1, Precedence::Flash, b"fire mission".to_vec());
        // an attacker without the key can compute a valid CRC, or a tag with the wrong key
        assert!(Frame::decode(&f.encode(None)?, Some(&key(9))).is_err());
        assert_eq!(
            Frame::decode(&f.encode(Some(&key(8)))?, Some(&key(9))),
            Err(FrameError::BadAuthTag)
        );
        Ok(())
    }

    #[test]
    fn random_and_mutated_input_never_panics() -> Result<(), FrameError> {
        let mut rng = Rng::new(1);
        for k in [None, Some(key(4))] {
            let valid = Frame::data(2, 3, Precedence::Priority, vec![7; 200]).encode(k.as_ref())?;
            for _ in 0..100_000 {
                let len = rng.below(300) as usize;
                let junk: Vec<u8> = (0..len).map(|_| rng.next_u32() as u8).collect();
                let _ = Frame::decode(&junk, k.as_ref());
                let mut m = valid.clone();
                for _ in 0..1 + rng.below(4) {
                    let i = rng.below(m.len() as u32) as usize;
                    m[i] = rng.next_u32() as u8;
                }
                if rng.below(2) == 0 {
                    m.truncate(rng.below(m.len() as u32) as usize);
                }
                let _ = Frame::decode(&m, k.as_ref());
            }
        }
        Ok(())
    }
}
