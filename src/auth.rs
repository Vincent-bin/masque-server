//! HTTP proxy authentication helpers.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::{Context, bail};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::rand::SecureRandom;
use zeroize::Zeroizing;

use crate::config::AuthSection;

const MAX_AUTHORIZATION_LEN: usize = 8 * 1024;

/// Maximum number of independently revocable credentials on one listener.
pub(crate) const MAX_BASIC_USERS_PER_LISTENER: usize = 4096;

/// An immutable set of Basic credentials for one listener.
pub(crate) struct BasicAuthenticator {
    users: HashMap<Vec<u8>, Arc<BasicCredential>>,
}

/// One selected credential. A request keeps this snapshot while Argon2 runs,
/// so a concurrent SIGHUP cannot pair its password with a different hash.
pub(crate) struct BasicCredential {
    password_hash: String,
}

/// Reloadable authentication state shared by every shard and established
/// HTTP/2 connection of one listener.
pub(crate) struct SharedBasicAuthenticator {
    current: RwLock<Arc<BasicAuthenticator>>,
}

/// Reject a username the Basic scheme cannot carry.
///
/// RFC 7617 joins the username and password with a colon before base64, so a
/// colon inside the username makes the pair ambiguous. Shared with
/// Configuration-editing commands also use this check before changing a file,
/// so an operator sees the error before any Argon2 work or write is attempted.
pub fn check_username(username: &str) -> anyhow::Result<()> {
    if username.is_empty() {
        bail!("auth.username must not be empty when authentication is enabled");
    }
    if username.contains(':') || username.chars().any(char::is_control) {
        bail!("auth.username must not contain ':' or control characters");
    }
    Ok(())
}

impl BasicAuthenticator {
    pub(crate) fn new(username: &str, password_hash: &str) -> anyhow::Result<Self> {
        Self::from_entries(std::iter::once((username, password_hash)))
    }

    /// Build the effective credential set from either the legacy scalar pair
    /// or repeated multi-user tables. Mixing the spellings is rejected so it
    /// is always clear which credentials are active.
    pub(crate) fn from_section(auth: &AuthSection) -> anyhow::Result<Self> {
        if !auth.users.is_empty() {
            if !auth.username.is_empty() || !auth.password_hash.is_empty() {
                bail!(
                    "auth.username/auth.password_hash cannot be combined with \
                     [[listeners.auth.users]]"
                );
            }
            return Self::from_entries(
                auth.users
                    .iter()
                    .map(|user| (user.username.as_str(), user.password_hash.as_str())),
            );
        }

        Self::new(&auth.username, &auth.password_hash)
    }

    fn from_entries<'a>(
        entries: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> anyhow::Result<Self> {
        let mut users = HashMap::new();
        for (index, (username, password_hash)) in entries.into_iter().enumerate() {
            if index >= MAX_BASIC_USERS_PER_LISTENER {
                bail!(
                    "a Basic listener may configure at most {MAX_BASIC_USERS_PER_LISTENER} users"
                );
            }
            check_username(username).with_context(|| format!("invalid Basic user {username:?}"))?;
            let parsed = PasswordHash::new(password_hash).with_context(|| {
                format!("Basic user {username:?} password_hash is not a valid PHC password hash")
            })?;
            if parsed.algorithm.as_str() != "argon2id" {
                bail!("Basic user {username:?} password_hash must use Argon2id");
            }

            let credential = Arc::new(BasicCredential {
                password_hash: password_hash.to_owned(),
            });
            if users
                .insert(username.as_bytes().to_vec(), credential)
                .is_some()
            {
                bail!("duplicate Basic username {username:?}");
            }
        }
        if users.is_empty() {
            bail!("a Basic listener must configure at least one user");
        }
        Ok(Self { users })
    }

    /// Validate a complete `Proxy-Authorization` field value, end to end.
    ///
    /// Only for tests: the request path must use [`precheck`](Self::precheck)
    /// plus [`BasicCredential::verify`] so the deliberately slow password hash
    /// stays off the event loop.
    #[cfg(test)]
    pub(crate) fn authenticate(&self, value: Option<&[u8]>) -> bool {
        match self.precheck(value) {
            AuthPrecheck::Rejected => false,
            AuthPrecheck::NeedsVerify {
                credential,
                password,
            } => credential.verify(&password),
        }
    }

    /// Run every cheap check, stopping before the password hash.
    ///
    /// Everything here is microseconds — parsing, base64, and one credential
    /// lookup — so a malformed or unknown-user request is rejected without
    /// ever paying for Argon2.
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

        let Some(credential) = self.users.get(username) else {
            return AuthPrecheck::Rejected;
        };

        AuthPrecheck::NeedsVerify {
            credential: Arc::clone(credential),
            password: Zeroizing::new(password.to_vec()),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.users.len()
    }
}

impl BasicCredential {
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

impl SharedBasicAuthenticator {
    pub(crate) fn new(auth: BasicAuthenticator) -> Self {
        Self {
            current: RwLock::new(Arc::new(auth)),
        }
    }

    pub(crate) fn precheck(&self, value: Option<&[u8]>) -> AuthPrecheck {
        self.current
            .read()
            .expect("Basic credential set poisoned")
            .precheck(value)
    }

    pub(crate) fn replace(&self, auth: BasicAuthenticator) -> usize {
        let count = auth.len();
        *self.current.write().expect("Basic credential set poisoned") = Arc::new(auth);
        count
    }
}

/// Result of the cheap half of authentication.
pub(crate) enum AuthPrecheck {
    /// Rejected without hashing.
    Rejected,
    /// Well formed and the username matches; the password still needs the
    /// slow verification.
    NeedsVerify {
        credential: Arc<BasicCredential>,
        password: Zeroizing<Vec<u8>>,
    },
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
    use crate::config::{AuthMode, BasicUser};

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

    fn authenticate_shared(auth: &SharedBasicAuthenticator, value: &[u8]) -> bool {
        match auth.precheck(Some(value)) {
            AuthPrecheck::Rejected => false,
            AuthPrecheck::NeedsVerify {
                credential,
                password,
            } => credential.verify(&password),
        }
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
    fn one_listener_accepts_multiple_independent_users() {
        let auth = BasicAuthenticator::from_section(&AuthSection {
            enabled: true,
            mode: AuthMode::Basic,
            username: String::new(),
            password_hash: String::new(),
            users: vec![
                BasicUser {
                    username: "alice".into(),
                    password_hash: hash_password(b"alice-secret").unwrap(),
                },
                BasicUser {
                    username: "bob".into(),
                    password_hash: hash_password(b"bob-secret").unwrap(),
                },
            ],
        })
        .unwrap();

        assert!(auth.authenticate(Some(&authorization("alice", "alice-secret"))));
        assert!(auth.authenticate(Some(&authorization("bob", "bob-secret"))));
        assert!(!auth.authenticate(Some(&authorization("alice", "bob-secret"))));
        assert!(!auth.authenticate(Some(&authorization("carol", "alice-secret"))));
    }

    #[test]
    fn multi_user_configuration_rejects_duplicates_and_legacy_mixing() {
        let hash = hash_password(b"secret").unwrap();
        let duplicate = AuthSection {
            enabled: true,
            mode: AuthMode::Basic,
            username: String::new(),
            password_hash: String::new(),
            users: vec![
                BasicUser {
                    username: "alice".into(),
                    password_hash: hash.clone(),
                },
                BasicUser {
                    username: "alice".into(),
                    password_hash: hash.clone(),
                },
            ],
        };
        assert!(BasicAuthenticator::from_section(&duplicate).is_err());

        let mixed = AuthSection {
            username: "legacy".into(),
            password_hash: hash.clone(),
            users: vec![BasicUser {
                username: "alice".into(),
                password_hash: hash,
            }],
            ..duplicate
        };
        assert!(BasicAuthenticator::from_section(&mixed).is_err());
    }

    #[test]
    fn shared_credentials_replace_atomically_for_future_requests() {
        let shared = SharedBasicAuthenticator::new(
            BasicAuthenticator::new("alice", &hash_password(b"old-secret").unwrap()).unwrap(),
        );
        let old_header = authorization("alice", "old-secret");
        let AuthPrecheck::NeedsVerify {
            credential: old_credential,
            password: old_password,
        } = shared.precheck(Some(&old_header))
        else {
            panic!("old credential should precheck");
        };

        shared.replace(
            BasicAuthenticator::new("alice", &hash_password(b"new-secret").unwrap()).unwrap(),
        );
        assert!(
            old_credential.verify(&old_password),
            "an already queued request keeps one coherent credential snapshot"
        );
        assert!(!authenticate_shared(&shared, &old_header));
        assert!(authenticate_shared(
            &shared,
            &authorization("alice", "new-secret")
        ));
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

        let AuthPrecheck::NeedsVerify {
            credential,
            password,
        } = auth.precheck(Some(good))
        else {
            panic!("valid credentials should reach verification");
        };
        assert!(credential.verify(&password));
        assert!(auth.authenticate(Some(good)));

        let AuthPrecheck::NeedsVerify {
            credential,
            password,
        } = auth.precheck(Some(bad))
        else {
            panic!("a wrong password is only detectable by verifying it");
        };
        assert!(!credential.verify(&password));
        assert!(!auth.authenticate(Some(bad)));
    }
}
