//! Wire format. Every field is bounds-checked on decode; malformed input returns an error, never panics.
//!
//! ```text
//! 0      2   3     4          5      9      13       17     19          19+len   23+len
//! | "LK" |ver| kind | precedence | seq  | ack   |  sack  | len | payload | CRC-32C |
//! ```
//! `ack` is the highest sequence number below which everything has been received; `sack` marks which of the 32
//! sequence numbers after `ack` have also arrived (selective acknowledgement).

use crate::crc::crc32c;

pub const MAGIC: [u8; 2] = *b"LK";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 19;
pub const MAX_PAYLOAD: usize = 1024;

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
}

impl Frame {
    pub fn data(seq: u32, precedence: Precedence, payload: Vec<u8>) -> Self {
        Frame {
            kind: Kind::Data,
            precedence,
            seq,
            ack: 0,
            sack: 0,
            payload,
        }
    }

    pub fn ack(ack: u32, sack: u32) -> Self {
        Frame {
            kind: Kind::Ack,
            precedence: Precedence::Flash,
            seq: 0,
            ack,
            sack,
            payload: Vec::new(),
        }
    }

    pub fn encoded_len(&self) -> usize {
        HEADER_LEN + self.payload.len() + 4
    }

    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.payload.len() > MAX_PAYLOAD {
            return Err(FrameError::PayloadTooLarge(self.payload.len()));
        }
        let mut b = Vec::with_capacity(self.encoded_len());
        b.extend_from_slice(&MAGIC);
        b.push(VERSION);
        b.push(self.kind as u8);
        b.push(self.precedence as u8);
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.ack.to_be_bytes());
        b.extend_from_slice(&self.sack.to_be_bytes());
        b.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        b.extend_from_slice(&self.payload);
        let crc = crc32c(&b);
        b.extend_from_slice(&crc.to_be_bytes());
        Ok(b)
    }

    pub fn decode(b: &[u8]) -> Result<Frame, FrameError> {
        if b.len() < HEADER_LEN + 4 {
            return Err(FrameError::TooShort);
        }
        // checksum first: a corrupted frame is rejected before any field is trusted
        let (body, crc) = b.split_at(b.len() - 4);
        if crc32c(body) != u32::from_be_bytes([crc[0], crc[1], crc[2], crc[3]]) {
            return Err(FrameError::BadChecksum);
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
        let len = u16::from_be_bytes([body[17], body[18]]) as usize;
        if len > MAX_PAYLOAD {
            return Err(FrameError::PayloadTooLarge(len));
        }
        if body.len() != HEADER_LEN + len {
            return Err(FrameError::LengthMismatch);
        }
        Ok(Frame {
            kind,
            precedence,
            seq: u32_at(5),
            ack: u32_at(9),
            sack: u32_at(13),
            payload: body[HEADER_LEN..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;

    #[test]
    fn round_trip() -> Result<(), FrameError> {
        let f = Frame::data(42, Precedence::Immediate, b"position report".to_vec());
        assert_eq!(Frame::decode(&f.encode()?)?, f);
        let a = Frame::ack(7, 0b1011);
        assert_eq!(Frame::decode(&a.encode()?)?, a);
        Ok(())
    }

    #[test]
    fn oversized_payload_is_refused() {
        assert_eq!(
            Frame::data(1, Precedence::Routine, vec![0; MAX_PAYLOAD + 1]).encode(),
            Err(FrameError::PayloadTooLarge(MAX_PAYLOAD + 1))
        );
    }

    #[test]
    fn every_single_bit_flip_is_detected() -> Result<(), FrameError> {
        let bytes = Frame::data(9, Precedence::Flash, b"contact bearing 270".to_vec()).encode()?;
        for i in 0..bytes.len() * 8 {
            let mut m = bytes.clone();
            m[i / 8] ^= 1 << (i % 8);
            assert!(Frame::decode(&m).is_err(), "bit {i} flip accepted");
        }
        Ok(())
    }

    #[test]
    fn random_and_mutated_input_never_panics() -> Result<(), FrameError> {
        let mut rng = Rng::new(1);
        let valid = Frame::data(3, Precedence::Priority, vec![7; 200]).encode()?;
        for _ in 0..200_000 {
            let len = rng.below(300) as usize;
            let junk: Vec<u8> = (0..len).map(|_| rng.next_u32() as u8).collect();
            let _ = Frame::decode(&junk);
            let mut m = valid.clone();
            for _ in 0..1 + rng.below(4) {
                let i = rng.below(m.len() as u32) as usize;
                m[i] = rng.next_u32() as u8;
            }
            if rng.below(2) == 0 {
                m.truncate(rng.below(m.len() as u32) as usize);
            }
            let _ = Frame::decode(&m);
        }
        Ok(())
    }
}
