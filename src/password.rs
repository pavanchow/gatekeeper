//! Salted password hashing.
//!
//! HONEST NOTE: this is a demo-grade construction, HMAC-SHA256 run in a
//! feedback loop for a configurable number of rounds ("gkdf-hmac-sha256").
//! It is not Argon2, not scrypt, not bcrypt, and it is not GPU-hardened.
//! Do not use it to protect real user passwords in production. It exists
//! here to show, readably, what "salt, stretch, compare" means end to end.

use crate::base64url;
use crate::error::{GatekeeperError, Result};
use crate::hmac::{constant_time_eq, hmac_sha256};
use std::fs::File;
use std::io::Read;

pub const MAX_PASSWORD_LEN: usize = 1024;
const SALT_LEN: usize = 16;
const OUTPUT_LEN: usize = 32;
const DEFAULT_ROUNDS: u32 = 100_000;
const ALGO_TAG: &str = "gkdf-hmac-sha256";

/// Hashes `password` with a fresh random salt and the default round count.
/// Returns a self-describing string: algo$rounds$salt_b64$hash_b64
pub fn hash(password: &str) -> Result<String> {
    hash_with_rounds(password, DEFAULT_ROUNDS)
}

pub fn hash_with_rounds(password: &str, rounds: u32) -> Result<String> {
    if password.len() > MAX_PASSWORD_LEN {
        return Err(GatekeeperError::PasswordTooLarge);
    }
    let salt = random_salt();
    let digest = stretch(password.as_bytes(), &salt, rounds);
    Ok(format!(
        "{}${}${}${}",
        ALGO_TAG,
        rounds,
        base64url::encode(&salt),
        base64url::encode(&digest)
    ))
}

/// Checks `password` against a hash string produced by `hash`.
/// Recomputes the stretch with the embedded salt and round count, then
/// compares in constant time. Never panics on a malformed hash string.
pub fn check(password: &str, encoded_hash: &str) -> Result<bool> {
    if password.len() > MAX_PASSWORD_LEN {
        return Err(GatekeeperError::PasswordTooLarge);
    }

    let fields: Vec<&str> = encoded_hash.split('$').collect();
    if fields.len() != 4 {
        return Err(GatekeeperError::MalformedHash);
    }
    let (algo, rounds_str, salt_b64, hash_b64) = (fields[0], fields[1], fields[2], fields[3]);
    if algo != ALGO_TAG {
        return Err(GatekeeperError::MalformedHash);
    }
    let rounds: u32 = rounds_str.parse().map_err(|_| GatekeeperError::MalformedHash)?;
    let salt = base64url::decode(salt_b64).map_err(|_| GatekeeperError::MalformedHash)?;
    let expected = base64url::decode(hash_b64).map_err(|_| GatekeeperError::MalformedHash)?;

    let actual = stretch(password.as_bytes(), &salt, rounds);
    Ok(constant_time_eq(&actual, &expected))
}

/// HMAC-SHA256 run in a feedback loop: round i feeds round i-1's output back
/// in as the message, keyed by the password each time. This is the "stretch"
/// that makes brute force costlier; it is not a substitute for Argon2/scrypt.
fn stretch(password: &[u8], salt: &[u8], rounds: u32) -> [u8; OUTPUT_LEN] {
    let mut state = hmac_sha256(password, salt);
    let rounds = rounds.max(1);
    for _ in 1..rounds {
        state = hmac_sha256(password, &state);
    }
    state
}

fn random_salt() -> [u8; SALT_LEN] {
    let mut buf = [0u8; SALT_LEN];
    if let Ok(mut f) = File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return buf;
        }
    }
    // Fallback: not cryptographically ideal, but keeps the function total
    // (never panics) on a platform without /dev/urandom.
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((nanos >> (i % 16 * 4)) & 0xff) as u8 ^ (i as u8);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_password_checks_out() {
        let h = hash_with_rounds("correct horse battery staple", 1000).unwrap();
        assert!(check("correct horse battery staple", &h).unwrap());
    }

    #[test]
    fn wrong_password_is_rejected() {
        let h = hash_with_rounds("correct horse battery staple", 1000).unwrap();
        assert!(!check("wrong password", &h).unwrap());
    }

    #[test]
    fn two_hashes_of_same_password_use_different_salts() {
        let a = hash_with_rounds("same password", 1000).unwrap();
        let b = hash_with_rounds("same password", 1000).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn malformed_hash_does_not_panic() {
        let result = check("anything", "not-a-valid-hash-string");
        assert!(result.is_err());
    }
}
