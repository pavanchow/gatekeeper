//! base64url (RFC 4648 section 5), no padding, implemented from scratch.

use crate::error::GatekeeperError;

const ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() * 4 + 2) / 3);
    let mut chunks = input.chunks_exact(3);

    for chunk in &mut chunks {
        let n = (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8 | chunk[2] as u32;
        out.push(ALPHABET[(n >> 18 & 0x3f) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 0x3f) as usize] as char);
        out.push(ALPHABET[(n >> 6 & 0x3f) as usize] as char);
        out.push(ALPHABET[(n & 0x3f) as usize] as char);
    }

    let rem = chunks.remainder();
    match rem.len() {
        1 => {
            let n = (rem[0] as u32) << 16;
            out.push(ALPHABET[(n >> 18 & 0x3f) as usize] as char);
            out.push(ALPHABET[(n >> 12 & 0x3f) as usize] as char);
        }
        2 => {
            let n = (rem[0] as u32) << 16 | (rem[1] as u32) << 8;
            out.push(ALPHABET[(n >> 18 & 0x3f) as usize] as char);
            out.push(ALPHABET[(n >> 12 & 0x3f) as usize] as char);
            out.push(ALPHABET[(n >> 6 & 0x3f) as usize] as char);
        }
        _ => {}
    }
    out
}

fn decode_char(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

pub fn decode(input: &str) -> Result<Vec<u8>, GatekeeperError> {
    let bytes = input.as_bytes();
    if bytes.iter().any(|b| *b == b'=') {
        return Err(GatekeeperError::InvalidBase64);
    }

    let mut out = Vec::with_capacity(bytes.len() * 3 / 4 + 3);
    let mut chunks = bytes.chunks_exact(4);

    for chunk in &mut chunks {
        let vals = [
            decode_char(chunk[0]).ok_or(GatekeeperError::InvalidBase64)?,
            decode_char(chunk[1]).ok_or(GatekeeperError::InvalidBase64)?,
            decode_char(chunk[2]).ok_or(GatekeeperError::InvalidBase64)?,
            decode_char(chunk[3]).ok_or(GatekeeperError::InvalidBase64)?,
        ];
        let n = (vals[0] as u32) << 18
            | (vals[1] as u32) << 12
            | (vals[2] as u32) << 6
            | vals[3] as u32;
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
    }

    let rem = chunks.remainder();
    match rem.len() {
        0 => {}
        2 => {
            let a = decode_char(rem[0]).ok_or(GatekeeperError::InvalidBase64)?;
            let b = decode_char(rem[1]).ok_or(GatekeeperError::InvalidBase64)?;
            let n = (a as u32) << 18 | (b as u32) << 12;
            out.push((n >> 16) as u8);
        }
        3 => {
            let a = decode_char(rem[0]).ok_or(GatekeeperError::InvalidBase64)?;
            let b = decode_char(rem[1]).ok_or(GatekeeperError::InvalidBase64)?;
            let c = decode_char(rem[2]).ok_or(GatekeeperError::InvalidBase64)?;
            let n = (a as u32) << 18 | (b as u32) << 12 | (c as u32) << 6;
            out.push((n >> 16) as u8);
            out.push((n >> 8) as u8);
        }
        _ => return Err(GatekeeperError::InvalidBase64),
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_arbitrary_bytes() {
        let cases: &[&[u8]] = &[b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"];
        for case in cases {
            let encoded = encode(case);
            let decoded = decode(&encoded).unwrap();
            assert_eq!(&decoded, case);
        }
    }

    #[test]
    fn rejects_padding_character() {
        assert!(decode("Zm9v=").is_err());
    }

    #[test]
    fn no_padding_in_output() {
        assert_eq!(encode(b"f"), "Zg");
        assert_eq!(encode(b"fo"), "Zm8");
        assert_eq!(encode(b"foo"), "Zm9v");
    }
}
