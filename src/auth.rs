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

    /// Validate a complete `Proxy-Authorization` field value, end to end.
    ///
    /// Only for tests: the request path must use [`precheck`](Self::precheck)
    /// plus [`verify`](Self::verify) so the deliberately slow password hash
    /// stays off the event loop.
    #[cfg(test)]
    pub(crate) fn authenticate(&self, value: Option<&[u8]>) -> bool {
        match self.precheck(value) {
            AuthPrecheck::Rejected => false,
            AuthPrecheck::NeedsVerify(password) => self.verify(&password),
        }
    }

    /// Run every cheap check, stopping before the password hash.
    ///
    /// Everything here is microseconds — parsing, base64, and a constant-time
    /// username comparison — so a malformed or wrong-user request is rejected
    /// without ever paying for Argon2.
    pub(crate) fn precheck(&self, value: Option<&[u8]>) -> AuthPrecheck {
        let Some(value) = value else {
            return AuthPrecheck::Rejected;
        };
        if value.len() > MAX_AUTHORIZATION_LEN {
            return AuthPrecheck::Rejected;
        }

        let Some(separator) = value.iter().position(|byte| byte.is_ascii_whitespace()) else {
            return AuthPrecheck::Rejected;
        };
        let (scheme, credentials) = value.split_at(separator);
        if !scheme.eq_ignore_ascii_case(b"basic") {
            return AuthPrecheck::Rejected;
        }

        let credentials = trim_ascii_whitespace(credentials);
        if credentials.is_empty() || credentials.iter().any(|byte| byte.is_ascii_whitespace()) {
            return AuthPrecheck::Rejected;
        }

        let decoded = match STANDARD.decode(credentials) {
            Ok(decoded) => Zeroizing::new(decoded),
            Err(_) => return AuthPrecheck::Rejected,
        };
        let Some(colon) = decoded.iter().position(|byte| *byte == b':') else {
            return AuthPrecheck::Rejected;
        };
        let (username, password_with_colon) = decoded.split_at(colon);
        let password = &password_with_colon[1..];

        if !bool::from(username.ct_eq(self.username.as_slice())) {
            return AuthPrecheck::Rejected;
        }

        AuthPrecheck::NeedsVerify(Zeroizing::new(password.to_vec()))
    }

    /// Verify a prechecked password against the configured hash.
    ///
    /// Argon2id is memory-hard by design — tens of milliseconds and ~19 MiB
    /// per call — so this must not run on the event loop.
    pub(crate) fn verify(&self, password: &[u8]) -> bool {
        let parsed = match PasswordHash::new(&self.password_hash) {
            Ok(parsed) => parsed,
            Err(_) => return false,
        };
        Argon2::default().verify_password(password, &parsed).is_ok()
    }
}

/// Result of the cheap half of authentication.
pub(crate) enum AuthPrecheck {
    /// Rejected without hashing.
    Rejected,
    /// Well formed and the username matches; the password still needs the
    /// slow verification.
    NeedsVerify(Zeroizing<Vec<u8>>),
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
    let salt = SaltString::encode_b64(&salt_bytes).context("failed to encode password salt")?;

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
        format!(
            "Basic {}",
            STANDARD.encode(format!("{username}:{password}"))
        )
        .into_bytes()
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

    /// The expensive hash must be reachable only for a well-formed request
    /// naming the configured user; everything else has to be refused cheaply.
    #[test]
    fn precheck_refuses_bad_requests_without_hashing() {
        let hash = hash_password(b"correct-horse").unwrap();
        let auth = BasicAuthenticator::new("alice", &hash).unwrap();

        for value in [
            None,
            Some(b"".as_slice()),
            Some(b"Bearer token".as_slice()),
            Some(b"Basic !!not-base64!!".as_slice()),
            // Right shape, wrong user.
            Some(b"Basic Ym9iOmNvcnJlY3QtaG9yc2U=".as_slice()),
        ] {
            assert!(
                matches!(auth.precheck(value), AuthPrecheck::Rejected),
                "expected a cheap rejection for {value:?}"
            );
        }
    }

    #[test]
    fn precheck_then_verify_matches_end_to_end_authentication() {
        let hash = hash_password(b"correct-horse").unwrap();
        let auth = BasicAuthenticator::new("alice", &hash).unwrap();
        let good = b"Basic YWxpY2U6Y29ycmVjdC1ob3JzZQ==".as_slice();
        let bad = b"Basic YWxpY2U6d3JvbmctcGFzcw==".as_slice();

        let AuthPrecheck::NeedsVerify(password) = auth.precheck(Some(good)) else {
            panic!("valid credentials should reach verification");
        };
        assert!(auth.verify(&password));
        assert!(auth.authenticate(Some(good)));

        let AuthPrecheck::NeedsVerify(password) = auth.precheck(Some(bad)) else {
            panic!("a wrong password is only detectable by verifying it");
        };
        assert!(!auth.verify(&password));
        assert!(!auth.authenticate(Some(bad)));
    }
}
