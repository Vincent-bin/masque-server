//! Client enrollment without an enrollment API.
//!
//! Clients in the Cloudflare WARP MASQUE family normally learn their key, their
//! tunnel addresses, and the endpoint's public key from a vendor registration
//! service. A self-hosted server has no such service, so the operator plays its
//! part: generate a key pair, keep the public half in `[[clients]]`, and hand
//! the private half to the client along with the addresses it was pinned to.
//!
//! This module produces both halves of that exchange from one call, so the two
//! sides cannot drift apart.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use boring::ec::{EcGroup, EcKey};
use boring::nid::Nid;
use boring::x509::X509;
use zeroize::Zeroize as _;

/// A freshly generated client key pair, in the encodings each side expects.
pub struct ClientKeyPair {
    /// SEC1 / RFC 5915 EC private key DER, base64 encoded.
    ///
    /// This is the `private_key` form these clients store: they parse it with
    /// an EC-specific parser, so PKCS#8 — what most tooling emits by default —
    /// is silently rejected.
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

/// Read the server certificate's public key as PEM.
///
/// These clients do not verify the certificate chain — the SNI they send rarely
/// matches the endpoint — and pin this key instead, comparing it byte for byte
/// against the leaf they are offered.
pub fn server_public_key_pem(cert_path: &Path) -> anyhow::Result<String> {
    let pem = std::fs::read(cert_path)
        .with_context(|| format!("failed to read {}", cert_path.display()))?;
    let cert = X509::from_pem(&pem)
        .with_context(|| format!("{} is not a PEM certificate", cert_path.display()))?;
    let key = cert
        .public_key()
        .context("server certificate has no public key")?;

    // A client that pins an ECDSA key will refuse anything else outright, so
    // catch it here rather than at the client's first connection attempt.
    if key.ec_key().is_err() {
        bail!(
            "{} does not use an ECDSA key; regenerate it with an EC key \
             (scripts/gen-certs.sh does this) or these clients cannot pin it",
            cert_path.display()
        );
    }

    let pem = key
        .public_key_to_pem()
        .context("failed to encode the server public key")?;
    String::from_utf8(pem).context("server public key PEM is not valid UTF-8")
}

/// Strip the armour from a PEM block, leaving the base64 DER body.
///
/// Some clients want the key this way rather than as PEM, and reject a value
/// that still carries the header lines or embedded newlines.
pub fn pem_to_base64_der(pem: &str) -> String {
    pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .flat_map(|line| line.chars().filter(|c| !c.is_ascii_whitespace()))
        .collect()
}

/// A `proxies:` entry for mihomo-style clients.
///
/// Same protocol as the JSON form, different spelling of the same four facts:
/// the key is base64 DER rather than PEM, the tunnel addresses are CIDR rather
/// than bare, and the endpoint splits into separate host and port fields.
pub fn mihomo_proxy_yaml(
    name: &str,
    private_key_b64: &str,
    server_public_key_b64: &str,
    endpoint: SocketAddr,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    mtu: usize,
) -> String {
    let mut block = String::from("proxies:\n");
    block.push_str(&format!("  - name: {}\n", yaml_string(name)));
    block.push_str("    type: masque\n");
    block.push_str(&format!("    server: {}\n", endpoint.ip()));
    block.push_str(&format!("    port: {}\n", endpoint.port()));
    block.push_str(&format!(
        "    private-key: {}\n",
        yaml_string(private_key_b64)
    ));
    block.push_str(&format!(
        "    public-key: {}\n",
        yaml_string(server_public_key_b64)
    ));
    // CIDR form, and a single-host prefix: the server assigns exactly this
    // address, not a subnet the client may pick from.
    if let Some(ipv4) = ipv4 {
        block.push_str(&format!("    ip: {ipv4}/32\n"));
    }
    if let Some(ipv6) = ipv6 {
        block.push_str(&format!("    ipv6: {ipv6}/128\n"));
    }
    block.push_str(&format!("    mtu: {mtu}\n"));
    block.push_str("    udp: true\n");
    block
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

/// The client-side JSON configuration.
///
/// `endpoint_v4` / `endpoint_v6` are bare addresses, not `host:port`: the port
/// is a separate client-side flag. The `id` and `access_token` fields belong to
/// the vendor API and are emitted empty so a client that reads them finds
/// something well formed rather than a missing key.
pub fn client_config_json(
    private_key_b64: &str,
    server_public_key_pem: &str,
    endpoint: IpAddr,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
) -> String {
    let (endpoint_v4, endpoint_v6) = match endpoint {
        IpAddr::V4(v4) => (v4.to_string(), String::new()),
        IpAddr::V6(v6) => (String::new(), v6.to_string()),
    };

    let fields = [
        ("private_key", private_key_b64.to_string()),
        ("endpoint_v4", endpoint_v4),
        ("endpoint_v6", endpoint_v6),
        ("endpoint_pub_key", server_public_key_pem.to_string()),
        ("id", String::new()),
        ("access_token", String::new()),
        ("ipv4", ipv4.map(|ip| ip.to_string()).unwrap_or_default()),
        ("ipv6", ipv6.map(|ip| ip.to_string()).unwrap_or_default()),
    ];

    let body = fields
        .iter()
        .map(|(key, value)| format!("  \"{key}\": {}", json_string(value)))
        .collect::<Vec<_>>()
        .join(",\n");

    format!("{{\n{body}\n}}\n")
}

/// Quote a value as a TOML basic string.
fn toml_string(value: &str) -> String {
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

/// Quote a value as a YAML double-quoted scalar.
///
/// Base64 can start with characters YAML treats specially, so these values are
/// always quoted rather than emitted bare.
fn yaml_string(value: &str) -> String {
    // YAML's double-quoted style uses the same escapes as JSON for everything
    // that appears in a key, an address, or a name.
    json_string(value)
}

/// Quote a value as a JSON string.
///
/// The PEM key carries newlines, so escaping is not optional here.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
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

    /// A key standing in for the server's, where only its encoding matters.
    fn throwaway_p256_key() -> boring::pkey::PKey<boring::pkey::Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        boring::pkey::PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
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

    /// The private key must round-trip through the SEC1 parser these clients
    /// use, and its public half must match what we told the server to expect.
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

        let parsed = config::parse_toml(&block).unwrap();
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

        let parsed = config::parse_toml(&block).unwrap();
        assert_eq!(parsed.clients[0].ipv4, None);
        assert_eq!(parsed.clients[0].ipv6, None);
    }

    #[test]
    fn client_json_escapes_the_multiline_pem_key() {
        let json = client_config_json(
            "cHJpdmF0ZQ==",
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
            "203.0.113.9".parse().unwrap(),
            Some("10.89.0.2".parse().unwrap()),
            None,
        );

        // A raw newline inside a JSON string would make the file unparseable.
        assert!(json.contains("\\n"));
        assert!(!json.contains("KEY-----\n-"));
        assert!(json.contains("\"endpoint_v4\": \"203.0.113.9\""));
        // The port travels as a client flag, so it must not leak into the field.
        assert!(!json.contains("203.0.113.9:443"));
        assert!(json.contains("\"ipv4\": \"10.89.0.2\""));
        assert!(json.contains("\"ipv6\": \"\""));
    }

    #[test]
    fn pem_to_base64_der_strips_armour_and_newlines() {
        let key = throwaway_p256_key();
        let pem = String::from_utf8(key.public_key_to_pem().unwrap()).unwrap();
        let stripped = pem_to_base64_der(&pem);

        assert!(!stripped.contains("-----"));
        assert!(!stripped.contains('\n'));
        // Must still be the same key, byte for byte, after the round trip.
        assert_eq!(stripped, STANDARD.encode(key.public_key_to_der().unwrap()));
    }

    #[test]
    fn mihomo_block_carries_cidr_addresses_and_a_split_endpoint() {
        let pair = generate_client_key().unwrap();
        let server_key = STANDARD.encode(throwaway_p256_key().public_key_to_der().unwrap());
        let yaml = mihomo_proxy_yaml(
            "laptop",
            &pair.private_key_b64,
            &server_key,
            "203.0.113.9:4433".parse().unwrap(),
            Some("10.89.0.2".parse().unwrap()),
            Some("fd00:abcd::2".parse().unwrap()),
            1420,
        );

        assert!(yaml.contains("type: masque"));
        // Host and port are separate fields, unlike the JSON form.
        assert!(yaml.contains("server: 203.0.113.9"));
        assert!(yaml.contains("port: 4433"));
        assert!(!yaml.contains("203.0.113.9:4433"));
        // Addresses are CIDR here, and single-host: the server pins exactly one.
        assert!(yaml.contains("ip: 10.89.0.2/32"));
        assert!(yaml.contains("ipv6: fd00:abcd::2/128"));
        assert!(yaml.contains("mtu: 1420"));
        // The server key must be bare base64, never PEM.
        assert!(yaml.contains(&format!("public-key: \"{server_key}\"")));
        assert!(!yaml.contains("-----BEGIN"));
    }

    #[test]
    fn mihomo_block_omits_addresses_that_were_not_pinned() {
        let pair = generate_client_key().unwrap();
        let yaml = mihomo_proxy_yaml(
            "phone",
            &pair.private_key_b64,
            "AAAA",
            "203.0.113.9:443".parse().unwrap(),
            None,
            None,
            1280,
        );
        assert!(!yaml.contains("ip:"));
        assert!(!yaml.contains("ipv6:"));
    }

    #[test]
    fn client_json_uses_the_v6_endpoint_field_for_a_v6_address() {
        let json = client_config_json(
            "a2V5",
            "pem",
            "2001:db8::1".parse().unwrap(),
            None,
            Some("fd00:abcd::2".parse().unwrap()),
        );
        assert!(json.contains("\"endpoint_v6\": \"2001:db8::1\""));
        assert!(json.contains("\"endpoint_v4\": \"\""));
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
    fn non_ec_server_certificate_is_rejected() {
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

        let error = server_public_key_pem(&path).unwrap_err();
        assert!(format!("{error:#}").contains("ECDSA"), "{error:#}");

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
