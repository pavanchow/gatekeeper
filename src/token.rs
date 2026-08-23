//! JWT-like signed tokens: base64url(header).base64url(payload).base64url(signature).
//! Signature is HMAC-SHA256 over the ASCII bytes of the first two segments joined by ".".

use crate::base64url;
use crate::error::{GatekeeperError, Result};
use crate::hmac::{constant_time_eq, hmac_sha256};

/// Hard ceiling on an encoded token's length, in bytes. A token near this size
/// is already unreasonable; this exists so a malicious huge token cannot force
/// unbounded allocation during parsing.
pub const MAX_TOKEN_LEN: usize = 8 * 1024;
/// Hard ceiling on a subject string, in bytes.
pub const MAX_SUBJECT_LEN: usize = 512;
/// Hard ceiling on a secret key, in bytes.
pub const MAX_SECRET_LEN: usize = 4 * 1024;

const HEADER_JSON: &str = r#"{"alg":"HS256","typ":"JWT"}"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    pub sub: String,
    pub iat: u64,
    pub exp: u64,
}

/// Issues a signed token for `sub`, expiring `ttl_secs` after `iat`.
pub fn issue(sub: &str, ttl_secs: u64, secret: &[u8], iat: u64) -> Result<String> {
    if sub.len() > MAX_SUBJECT_LEN {
        return Err(GatekeeperError::SubjectTooLarge);
    }
    if secret.len() > MAX_SECRET_LEN {
        return Err(GatekeeperError::SecretTooLarge);
    }
    let exp = iat.saturating_add(ttl_secs);

    let header_b64 = base64url::encode(HEADER_JSON.as_bytes());
    let payload_json = encode_claims(&Claims {
        sub: sub.to_string(),
        iat,
        exp,
    });
    let payload_b64 = base64url::encode(payload_json.as_bytes());

    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let tag = hmac_sha256(secret, signing_input.as_bytes());
    let sig_b64 = base64url::encode(&tag);

    Ok(format!("{}.{}", signing_input, sig_b64))
}

/// Verifies a token's signature and expiry, returning the claims on success.
/// Recomputes the HMAC over the received segments and compares in constant
/// time; a flipped payload byte or a wrong secret both land on BadSignature.
pub fn verify(token: &str, secret: &[u8], now: u64) -> Result<Claims> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(GatekeeperError::TokenTooLarge);
    }
    if secret.len() > MAX_SECRET_LEN {
        return Err(GatekeeperError::SecretTooLarge);
    }

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(GatekeeperError::MalformedToken);
    }
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

    let header_bytes = base64url::decode(header_b64)?;
    if header_bytes != HEADER_JSON.as_bytes() {
        return Err(GatekeeperError::UnsupportedAlgorithm);
    }

    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let expected_tag = hmac_sha256(secret, signing_input.as_bytes());
    let given_tag = base64url::decode(sig_b64)?;

    if !constant_time_eq(&expected_tag, &given_tag) {
        return Err(GatekeeperError::BadSignature);
    }

    let payload_bytes = base64url::decode(payload_b64)?;
    let payload_json =
        std::str::from_utf8(&payload_bytes).map_err(|_| GatekeeperError::InvalidClaims)?;
    let claims = decode_claims(payload_json)?;

    if claims.sub.len() > MAX_SUBJECT_LEN {
        return Err(GatekeeperError::SubjectTooLarge);
    }
    if now >= claims.exp {
        return Err(GatekeeperError::Expired);
    }

    Ok(claims)
}

fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn encode_claims(claims: &Claims) -> String {
    format!(
        r#"{{"sub":"{}","iat":{},"exp":{}}}"#,
        escape_json_string(&claims.sub),
        claims.iat,
        claims.exp
    )
}

/// Minimal, non-panicking decoder for the exact claims shape this crate emits:
/// {"sub":"...","iat":N,"exp":N} in that field order. Not a general JSON parser.
fn decode_claims(json: &str) -> Result<Claims> {
    let json = json.trim();
    let inner = json
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or(GatekeeperError::InvalidClaims)?;

    let mut sub: Option<String> = None;
    let mut iat: Option<u64> = None;
    let mut exp: Option<u64> = None;

    for field in split_top_level(inner) {
        let mut kv = field.splitn(2, ':');
        let key = kv.next().ok_or(GatekeeperError::InvalidClaims)?.trim();
        let value = kv.next().ok_or(GatekeeperError::InvalidClaims)?.trim();
        let key = unquote(key)?;

        match key.as_str() {
            "sub" => sub = Some(unescape_json_string(&unquote(value)?)),
            "iat" => iat = Some(value.parse().map_err(|_| GatekeeperError::InvalidClaims)?),
            "exp" => exp = Some(value.parse().map_err(|_| GatekeeperError::InvalidClaims)?),
            _ => {}
        }
    }

    Ok(Claims {
        sub: sub.ok_or(GatekeeperError::InvalidClaims)?,
        iat: iat.ok_or(GatekeeperError::InvalidClaims)?,
        exp: exp.ok_or(GatekeeperError::InvalidClaims)?,
    })
}

fn split_top_level(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    let mut start = 0usize;

    for (i, c) in s.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

fn unquote(s: &str) -> Result<String> {
    let s = s.trim();
    let stripped = s
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or(GatekeeperError::InvalidClaims)?;
    Ok(stripped.to_string())
}

fn unescape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some(other) => out.push(other),
                None => {}
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-secret-key";

    #[test]
    fn issue_then_verify_roundtrips_claims() {
        let token = issue("alice", 3600, SECRET, 1_000_000).unwrap();
        let claims = verify(&token, SECRET, 1_000_500).unwrap();
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.iat, 1_000_000);
        assert_eq!(claims.exp, 1_003_600);
    }

    #[test]
    fn tampered_payload_byte_fails_verification() {
        let token = issue("alice", 3600, SECRET, 1_000_000).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let mut payload_bytes = base64url::decode(parts[1]).unwrap();
        let last = payload_bytes.len() - 1;
        payload_bytes[last] ^= 0x01;
        let tampered_payload = base64url::encode(&payload_bytes);
        let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

        let result = verify(&tampered_token, SECRET, 1_000_500);
        assert_eq!(result.unwrap_err(), GatekeeperError::BadSignature);
    }

    #[test]
    fn expired_token_is_rejected() {
        let token = issue("alice", 10, SECRET, 1_000_000).unwrap();
        let result = verify(&token, SECRET, 1_000_011);
        assert_eq!(result.unwrap_err(), GatekeeperError::Expired);
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let token = issue("alice", 3600, SECRET, 1_000_000).unwrap();
        let result = verify(&token, b"wrong-secret", 1_000_500);
        assert_eq!(result.unwrap_err(), GatekeeperError::BadSignature);
    }

    #[test]
    fn malformed_token_does_not_panic() {
        let result = verify("not-a-token", SECRET, 0);
        assert!(result.is_err());
    }
}
