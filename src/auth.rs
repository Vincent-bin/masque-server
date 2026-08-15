//! HTTP proxy authentication helpers.

use anyhow::{Context, bail};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::rand::SecureRandom;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAX_AUTHORIZATION_LEN: usize = 8 * 1024;

/// Validates RFC 7617 Basic proxy credentials against an Argon2id hash.
pub(crate) struct BasicAuthenticator {
    username: Vec<u8>,
    password_hash: String,
}

impl BasicAuthenticator {
    pub(crate) fn new(username: &str, password_hash: &str) -> anyhow::Result<Self> {
        if username.is_empty() {
            bail!("auth.username must not be empty when authentication is enabled");
        }
        if username.contains(':') || username.chars().any(char::is_control) {
            bail!("auth.username must not contain ':' or control characters");
        }

        let parsed = PasswordHash::new(password_hash)
            .context("auth.password_hash is not a valid PHC password hash")?;
        if parsed.algorithm.as_str() != "argon2id" {
            bail!("auth.password_hash must use Argon2id");
        }

        Ok(Self {
            username: username.as_bytes().to_vec(),
            password_hash: password_hash.to_owned(),
        })
    }

    /// Validate a complete `Proxy-Authorization` field value.
    pub(crate) fn authenticate(&self, value: Option<&[u8]>) -> bool {
        let Some(value) = value else {
            return false;
        };
        if value.len() > MAX_AUTHORIZATION_LEN {
            return false;
        }

        let Some(separator) = value.iter().position(|byte| byte.is_ascii_whitespace()) else {
            return false;
        };
        let (scheme, credentials) = value.split_at(separator);
        if !scheme.eq_ignore_ascii_case(b"basic") {
            return false;
        }

        let credentials = trim_ascii_whitespace(credentials);
        if credentials.is_empty() || credentials.iter().any(|byte| byte.is_ascii_whitespace()) {
            return false;
        }

        let decoded = match STANDARD.decode(credentials) {
            Ok(decoded) => Zeroizing::new(decoded),
            Err(_) => return false,
        };
        let Some(colon) = decoded.iter().position(|byte| *byte == b':') else {
            return false;
        };
        let (username, password_with_colon) = decoded.split_at(colon);
        let password = &password_with_colon[1..];

        if !bool::from(username.ct_eq(self.username.as_slice())) {
            return false;
        }

        let parsed = match PasswordHash::new(&self.password_hash) {
            Ok(parsed) => parsed,
            Err(_) => return false,
        };
        Argon2::default().verify_password(password, &parsed).is_ok()
    }
}

/// Hash a password using Argon2id's current recommended defaults and a fresh
/// 128-bit salt. The returned PHC string is suitable for `auth.password_hash`.
pub fn hash_password(password: &[u8]) -> anyhow::Result<String> {
    if password.is_empty() {
        bail!("password must not be empty");
    }

    let mut salt_bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut salt_bytes)
        .map_err(|_| anyhow::anyhow!("failed to generate password salt"))?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .context("failed to encode password salt")?;

    Ok(Argon2::new(
        Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    )
    .hash_password(password, &salt)
    .context("failed to hash password")?
    .to_string())
}

fn trim_ascii_whitespace(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;

    const USERNAME: &str = "test-user";
    const PASSWORD: &str = "correct horse:battery staple";

    fn password_hash() -> &'static str {
        static HASH: OnceLock<String> = OnceLock::new();
        HASH.get_or_init(|| hash_password(PASSWORD.as_bytes()).unwrap())
    }

    fn authorization(username: &str, password: &str) -> Vec<u8> {
        format!("Basic {}", STANDARD.encode(format!("{username}:{password}"))).into_bytes()
    }

    #[test]
    fn accepts_valid_basic_credentials() {
        let auth = BasicAuthenticator::new(USERNAME, password_hash()).unwrap();
        assert!(auth.authenticate(Some(&authorization(USERNAME, PASSWORD))));
    }

    #[test]
    fn scheme_is_case_insensitive_and_password_may_contain_colon() {
        let auth = BasicAuthenticator::new(USERNAME, password_hash()).unwrap();
        let mut value = authorization(USERNAME, PASSWORD);
        value[..5].copy_from_slice(b"bAsIc");
        assert!(auth.authenticate(Some(&value)));
    }

    #[test]
    fn rejects_missing_malformed_and_wrong_credentials() {
        let auth = BasicAuthenticator::new(USERNAME, password_hash()).unwrap();
        assert!(!auth.authenticate(None));
        assert!(!auth.authenticate(Some(b"Bearer token")));
        assert!(!auth.authenticate(Some(b"Basic not-base64!")));
        assert!(!auth.authenticate(Some(&authorization("other", PASSWORD))));
        assert!(!auth.authenticate(Some(&authorization(USERNAME, "wrong"))));
    }

    #[test]
    fn rejects_invalid_configuration() {
        assert!(BasicAuthenticator::new("", password_hash()).is_err());
        assert!(BasicAuthenticator::new("bad:name", password_hash()).is_err());
        assert!(BasicAuthenticator::new(USERNAME, "not-a-hash").is_err());
    }

    #[test]
    fn generated_hash_is_argon2id_and_salted() {
        let first = hash_password(b"secret").unwrap();
        let second = hash_password(b"secret").unwrap();
        assert!(first.starts_with("$argon2id$v=19$"));
        assert_ne!(first, second);
    }
}
