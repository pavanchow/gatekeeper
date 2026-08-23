//! HMAC-SHA256 implemented from scratch (RFC 2104 / FIPS 198-1), no crypto crates.

use crate::sha256::sha256;

const BLOCK_SIZE: usize = 64;

/// Computes HMAC-SHA256(key, message), returning a 32-byte tag.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = sha256(key);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner_input = Vec::with_capacity(BLOCK_SIZE + message.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(message);
    let inner_hash = sha256(&inner_input);

    let mut outer_input = Vec::with_capacity(BLOCK_SIZE + 32);
    outer_input.extend_from_slice(&opad);
    outer_input.extend_from_slice(&inner_hash);
    sha256(&outer_input)
}

/// Constant-time comparison. Always inspects every byte of both slices;
/// never short-circuits on the first mismatch. Returns false immediately
/// only on a length mismatch, which is not a secret-dependent branch.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 4231 test case 1
    #[test]
    fn rfc4231_case_1() {
        let key = from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let tag = hmac_sha256(&key, data);
        assert_eq!(
            hex(&tag),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    // RFC 4231 test case 2
    #[test]
    fn rfc4231_case_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let tag = hmac_sha256(key, data);
        assert_eq!(
            hex(&tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    // RFC 4231 test case 3
    #[test]
    fn rfc4231_case_3() {
        let key = from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let data = from_hex(&"dd".repeat(50));
        let tag = hmac_sha256(&key, &data);
        assert_eq!(
            hex(&tag),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    // RFC 4231 test case 6 (key longer than block size)
    #[test]
    fn rfc4231_case_6() {
        let key = from_hex(&"aa".repeat(131));
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let tag = hmac_sha256(&key, data);
        assert_eq!(
            hex(&tag),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn constant_time_eq_rejects_unequal_tags() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 5];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_accepts_equal_tags() {
        let a = [9u8, 8, 7, 6];
        let b = [9u8, 8, 7, 6];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_rejects_length_mismatch() {
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2]));
    }
}
