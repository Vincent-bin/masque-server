use std::io::Read as _;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

use crate::identity::ClientIdentity;
use crate::report::ProbeFailure;

pub enum Credentials {
    None,
    Basic(BasicCredentials),
    ClientCertificate(ClientIdentity),
}

pub struct BasicCredentials {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl BasicCredentials {
    pub fn from_stdin(username: String) -> Result<Self, ProbeFailure> {
        if username.is_empty() || username.contains(':') || username.chars().any(char::is_control) {
            return Err(ProbeFailure::new(
                "INVALID_CREDENTIALS",
                "Basic username must be non-empty and contain no colon or control character",
            ));
        }

        let mut password = Zeroizing::new(String::new());
        std::io::stdin()
            .read_to_string(&mut password)
            .map_err(|error| {
                ProbeFailure::new(
                    "INVALID_CREDENTIALS",
                    format!("could not read password from stdin: {error}"),
                )
            })?;
        if password.ends_with('\n') {
            password.pop();
            if password.ends_with('\r') {
                password.pop();
            }
        }
        if password.is_empty() || password.chars().any(char::is_control) {
            return Err(ProbeFailure::new(
                "INVALID_CREDENTIALS",
                "Basic password must be non-empty and contain no control character",
            ));
        }

        Ok(Self {
            username: Zeroizing::new(username),
            password,
        })
    }

    pub fn authorization(&self) -> Zeroizing<String> {
        let mut joined = Zeroizing::new(String::with_capacity(
            self.username.len() + self.password.len() + 1,
        ));
        joined.push_str(&self.username);
        joined.push(':');
        joined.push_str(&self.password);
        let encoded = STANDARD.encode(joined.as_bytes());
        Zeroizing::new(format!("Basic {encoded}"))
    }
}

impl Credentials {
    pub fn authorization(&self) -> Option<Zeroizing<String>> {
        match self {
            Self::Basic(credentials) => Some(credentials.authorization()),
            Self::None | Self::ClientCertificate(_) => None,
        }
    }

    pub fn client_identity(&self) -> Option<&ClientIdentity> {
        match self {
            Self::ClientCertificate(identity) => Some(identity),
            Self::None | Self::Basic(_) => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Basic(_) => "basic",
            Self::ClientCertificate(_) => "client_cert",
        }
    }
}
