//! Generate a certificate key pair and protocol connection details for local enrollment.
//!
//! Keep the public key in the server roster and transfer the private key with
//! the endpoint and pinned addresses through a private channel.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::str::FromStr as _;

use anyhow::{Context, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use boring::ec::{EcGroup, EcKey};
use boring::nid::Nid;
use boring::x509::X509;
use zeroize::Zeroize as _;

use crate::config::ListenerTransport;

/// A freshly generated client key pair, in the encodings each side expects.
pub struct ClientKeyPair {
    /// SEC1 / RFC 5915 EC private key DER, base64 encoded.
    pub private_key_b64: String,
    /// SubjectPublicKeyInfo DER, base64 encoded. Goes in `[[clients]]`.
    pub public_key_b64: String,
}

impl Drop for ClientKeyPair {
    fn drop(&mut self) {
        self.private_key_b64.zeroize();
    }
}

/// Generate a P-256 key pair for one client.
pub fn generate_client_key() -> anyhow::Result<ClientKeyPair> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .context("failed to load the P-256 curve")?;
    let key = EcKey::generate(&group).context("failed to generate a P-256 key")?;

    let private_key_b64 = STANDARD.encode(
        key.private_key_to_der()
            .context("failed to encode the private key")?,
    );

    let public =
        boring::pkey::PKey::from_ec_key(key).context("failed to wrap the generated key")?;
    let public_key_b64 = STANDARD.encode(
        public
            .public_key_to_der()
            .context("failed to encode the public key")?,
    );

    Ok(ClientKeyPair {
        private_key_b64,
        public_key_b64,
    })
}

/// Read the server certificate's public key in PEM form for key pinning.
pub fn server_public_key_pem(cert_path: &Path) -> anyhow::Result<String> {
    let pem = std::fs::read(cert_path)
        .with_context(|| format!("failed to read {}", cert_path.display()))?;
    let cert = X509::from_pem(&pem)
        .with_context(|| format!("{} is not a PEM certificate", cert_path.display()))?;
    let key = cert
        .public_key()
        .context("server certificate has no public key")?;

    let pem = key
        .public_key_to_pem()
        .context("failed to encode the server public key")?;
    String::from_utf8(pem).context("server public key PEM is not valid UTF-8")
}

/// Public address placed in a generated client configuration.
///
/// Listener addresses such as `[::]:8449` describe where the server binds,
/// not what a remote client dials, so credential-management commands require
/// this value explicitly instead of guessing from the server configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientEndpoint {
    pub host: String,
    pub port: u16,
}

impl ClientEndpoint {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        if value.contains('@') {
            bail!("client endpoint must not contain user information");
        }
        let authority = http::uri::Authority::from_str(value)
            .with_context(|| format!("invalid client endpoint {value:?}"))?;
        let port = authority
            .port_u16()
            .with_context(|| format!("client endpoint {value:?} has no port"))?;
        if port == 0 {
            bail!("client endpoint port must be between 1 and 65535");
        }
        let host = authority.host();
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        if host.is_empty()
            || host
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            bail!("client endpoint host is empty or contains whitespace");
        }
        if IpAddr::from_str(host).is_err()
            && !host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        {
            bail!(
                "client endpoint host must be an IP address or an ASCII DNS name containing only letters, digits, dots, and hyphens"
            );
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }
}

impl std::fmt::Display for ClientEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Export a Basic account while its plaintext password is available.
pub fn basic_client_config_json(
    name: Option<&str>,
    endpoint: &ClientEndpoint,
    transport: ListenerTransport,
    username: &str,
    password: &str,
) -> serde_json::Result<String> {
    #[derive(serde::Serialize)]
    struct BasicConfig<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<&'a str>,
        endpoint: String,
        transport: ListenerTransport,
        username: &'a str,
        password: &'a str,
    }
    json_config(&BasicConfig {
        name,
        endpoint: endpoint.to_string(),
        transport,
        username,
        password,
    })
}

/// The `[[clients]]` block to append to the server's config file.
pub fn clients_toml_block(
    name: &str,
    public_key_b64: &str,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
) -> String {
    let mut block = String::from("[[clients]]\n");
    block.push_str(&format!("name = {}\n", toml_string(name)));
    block.push_str(&format!("public_key = {}\n", toml_string(public_key_b64)));
    if let Some(ipv4) = ipv4 {
        block.push_str(&format!("ipv4 = \"{ipv4}\"\n"));
    }
    if let Some(ipv6) = ipv6 {
        block.push_str(&format!("ipv6 = \"{ipv6}\"\n"));
    }
    block
}

/// Create a new client configuration without exposing or replacing its key.
///
/// `create_new` refuses existing paths (including symlinks), avoiding both
/// accidental key loss and symlink-based clobbering when enrollment is run as
/// root. On Unix the private-key file is created owner-readable/writable only;
/// the mode is applied atomically at creation rather than repaired afterwards.
pub fn write_client_config(path: &Path, contents: &str) -> anyhow::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let mut file = options.open(path).with_context(|| {
        format!(
            "failed to create {} (refusing to overwrite an existing path)",
            path.display()
        )
    })?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))?;
    Ok(())
}

/// Export certificate enrollment details with the full public endpoint.
pub fn client_config_json(
    private_key_b64: &str,
    server_public_key_pem: &str,
    endpoint: SocketAddr,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
) -> serde_json::Result<String> {
    #[derive(serde::Serialize)]
    struct CertificateConfig<'a> {
        endpoint: SocketAddr,
        private_key: &'a str,
        endpoint_pub_key: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        ipv4: Option<Ipv4Addr>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ipv6: Option<Ipv6Addr>,
    }
    json_config(&CertificateConfig {
        endpoint,
        private_key: private_key_b64,
        endpoint_pub_key: server_public_key_pem,
        ipv4,
        ipv6,
    })
}

fn json_config(value: &impl serde::Serialize) -> serde_json::Result<String> {
    let mut json = serde_json::to_string_pretty(value)?;
    json.push('\n');
    Ok(json)
}

/// Quote a value as a TOML basic string.
pub(crate) fn toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_identity::{ClientRegistry, spki_from_cert_der};
    use crate::config::{self, ClientEntry};

    fn parse_with_listener(fragment: &str) -> config::ServerConfig {
        config::parse_toml(&format!(
            "{fragment}\n[[listeners]]\nlisten_addr = \"127.0.0.1:443\"\n\
             [listeners.auth]\nenabled = false\n"
        ))
        .unwrap()
    }

    #[test]
    fn generated_public_key_is_accepted_by_the_roster_parser() {
        let pair = generate_client_key().unwrap();
        let entry = ClientEntry {
            name: "laptop".into(),
            public_key: pair.public_key_b64.clone(),
            ipv4: None,
            ipv6: None,
        };
        // The whole point of the pair: what enrollment prints has to be what
        // the server accepts, with no reformatting in between.
        assert!(ClientRegistry::from_config(&[entry]).is_ok());
    }

    /// The SEC1 private key must match the public key in the server roster.
    #[test]
    fn private_key_is_sec1_der_matching_the_published_public_key() {
        let pair = generate_client_key().unwrap();
        let der = STANDARD.decode(&pair.private_key_b64).unwrap();

        let key = EcKey::private_key_from_der(&der).expect("must parse as a SEC1 EC private key");
        let public = boring::pkey::PKey::from_ec_key(key).unwrap();
        assert_eq!(
            STANDARD.encode(public.public_key_to_der().unwrap()),
            pair.public_key_b64
        );
    }

    #[test]
    fn each_call_generates_a_distinct_key() {
        let first = generate_client_key().unwrap();
        let second = generate_client_key().unwrap();
        assert_ne!(first.private_key_b64, second.private_key_b64);
        assert_ne!(first.public_key_b64, second.public_key_b64);
    }

    #[test]
    fn clients_block_parses_back_into_the_configured_roster() {
        let pair = generate_client_key().unwrap();
        let block = clients_toml_block(
            "my laptop",
            &pair.public_key_b64,
            Some("10.89.0.2".parse().unwrap()),
            Some("fd00:abcd::2".parse().unwrap()),
        );

        let parsed = parse_with_listener(&block);
        assert_eq!(parsed.clients.len(), 1);
        assert_eq!(parsed.clients[0].name, "my laptop");
        assert_eq!(parsed.clients[0].public_key, pair.public_key_b64);
        assert_eq!(parsed.clients[0].ipv4.as_deref(), Some("10.89.0.2"));
        assert_eq!(parsed.clients[0].ipv6.as_deref(), Some("fd00:abcd::2"));
        assert!(ClientRegistry::from_config(&parsed.clients).is_ok());
    }

    #[test]
    fn clients_block_omits_addresses_that_were_not_pinned() {
        let pair = generate_client_key().unwrap();
        let block = clients_toml_block("phone", &pair.public_key_b64, None, None);
        assert!(!block.contains("ipv4"));
        assert!(!block.contains("ipv6"));

        let parsed = parse_with_listener(&block);
        assert_eq!(parsed.clients[0].ipv4, None);
        assert_eq!(parsed.clients[0].ipv6, None);
    }

    #[test]
    fn certificate_json_preserves_keys_and_the_full_endpoint() {
        let key = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n";
        let json = client_config_json(
            "cHJpdmF0ZQ==",
            key,
            "[2001:db8::1]:8449".parse().unwrap(),
            Some("192.0.2.2".parse().unwrap()),
            None,
        )
        .unwrap();
        let data: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(data["endpoint"], "[2001:db8::1]:8449");
        assert_eq!(data["private_key"], "cHJpdmF0ZQ==");
        assert_eq!(data["endpoint_pub_key"], key);
        assert_eq!(data["ipv4"], "192.0.2.2");
        assert!(data.get("ipv6").is_none());
    }

    #[test]
    fn basic_json_preserves_transport_and_credentials() {
        let endpoint = ClientEndpoint::parse("[2001:db8::1]:443").unwrap();
        let json = basic_client_config_json(
            Some("phone"),
            &endpoint,
            ListenerTransport::Http2,
            "alice",
            "password with spaces, commas and \"quotes\"",
        )
        .unwrap();
        let data: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(data["name"], "phone");
        assert_eq!(data["endpoint"], "[2001:db8::1]:443");
        assert_eq!(data["transport"], "http2");
        assert_eq!(data["username"], "alice");
        assert_eq!(
            data["password"],
            "password with spaces, commas and \"quotes\""
        );
    }

    #[test]
    fn client_endpoint_rejects_user_information_and_invalid_ports() {
        assert!(ClientEndpoint::parse("user@proxy.example:443").is_err());
        assert!(ClientEndpoint::parse("proxy.example:0").is_err());
        assert!(ClientEndpoint::parse("proxy.example,udp-relay=true:443").is_err());
    }

    #[test]
    fn client_config_file_is_private_and_never_overwritten() {
        let dir = std::env::temp_dir().join(format!(
            "masque-enroll-write-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client.json");

        write_client_config(&path, "first-secret").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first-secret");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let error = write_client_config(&path, "replacement").unwrap_err();
        assert!(format!("{error:#}").contains("refusing to overwrite"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first-secret");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn server_public_key_is_read_from_a_pem_certificate() {
        // Build a throwaway EC certificate rather than depending on a fixture.
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = boring::pkey::PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut builder = boring::x509::X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(
                &boring::bn::BigNum::from_u32(1)
                    .unwrap()
                    .to_asn1_integer()
                    .unwrap(),
            )
            .unwrap();
        builder
            .set_not_before(&boring::asn1::Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&boring::asn1::Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .sign(&key, boring::hash::MessageDigest::sha256())
            .unwrap();
        let cert = builder.build();

        let dir = std::env::temp_dir().join(format!("masque-enroll-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.crt");
        std::fs::write(&path, cert.to_pem().unwrap()).unwrap();

        let pem = server_public_key_pem(&path).unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));

        // The pinned key must be the certificate's own key, or the client would
        // reject the very server that issued it this config.
        let from_cert = spki_from_cert_der(&cert.to_der().unwrap()).unwrap();
        let pinned = boring::pkey::PKey::public_key_from_pem(pem.as_bytes()).unwrap();
        assert_eq!(pinned.public_key_to_der().unwrap(), from_cert);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rsa_server_certificate_can_be_pinned() {
        let key = boring::pkey::PKey::from_rsa(boring::rsa::Rsa::generate(2048).unwrap()).unwrap();
        let mut builder = boring::x509::X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(
                &boring::bn::BigNum::from_u32(1)
                    .unwrap()
                    .to_asn1_integer()
                    .unwrap(),
            )
            .unwrap();
        builder
            .set_not_before(&boring::asn1::Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&boring::asn1::Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .sign(&key, boring::hash::MessageDigest::sha256())
            .unwrap();

        let dir = std::env::temp_dir().join(format!("masque-enroll-rsa-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rsa.crt");
        std::fs::write(&path, builder.build().to_pem().unwrap()).unwrap();

        let pem = server_public_key_pem(&path).unwrap();
        let pinned = boring::pkey::PKey::public_key_from_pem(pem.as_bytes()).unwrap();
        assert!(pinned.public_eq(&key));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_certificate_is_reported_with_its_path() {
        let error = server_public_key_pem(Path::new("/nonexistent/masque/server.crt")).unwrap_err();
        assert!(
            format!("{error:#}").contains("/nonexistent/masque/server.crt"),
            "{error:#}"
        );
    }
}
