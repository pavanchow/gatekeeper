//! Typed errors. Nothing in this crate panics on malformed input.

use std::fmt;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum GatekeeperError {
    TokenTooLarge,
    MalformedToken,
    InvalidBase64,
    InvalidClaims,
    BadSignature,
    Expired,
    SubjectTooLarge,
    SecretTooLarge,
    PasswordTooLarge,
    MalformedHash,
    UnsupportedAlgorithm,
}

impl fmt::Display for GatekeeperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            GatekeeperError::TokenTooLarge => "token exceeds the maximum allowed size",
            GatekeeperError::MalformedToken => "token is not in header.payload.signature form",
            GatekeeperError::InvalidBase64 => "token segment is not valid base64url",
            GatekeeperError::InvalidClaims => "payload does not decode to valid claims",
            GatekeeperError::BadSignature => "signature does not match, token rejected",
            GatekeeperError::Expired => "token has expired",
            GatekeeperError::SubjectTooLarge => "subject exceeds the maximum allowed size",
            GatekeeperError::SecretTooLarge => "secret exceeds the maximum allowed size",
            GatekeeperError::PasswordTooLarge => "password exceeds the maximum allowed size",
            GatekeeperError::MalformedHash => "password hash is not in the expected format",
            GatekeeperError::UnsupportedAlgorithm => "token header names an unsupported algorithm",
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for GatekeeperError {}

pub type Result<T> = std::result::Result<T, GatekeeperError>;
