//! Pre-registered client identities for TLS client-certificate authentication.
//!
//! Clients built against Cloudflare's WARP MASQUE endpoint authenticate with a
//! TLS client certificate rather than `Proxy-Authorization`, and the
//! certificate is self-signed, freshly minted per connection, and carries no
//! usable subject: only the key inside it identifies the caller. So the roster
//! is keyed by public key, and the certificate around it is treated as a
//! disposable envelope.
//!
//! Nothing here talks to an enrollment API. An operator generates a key pair
//! per client, records the public key in `[[clients]]`, and hands the private
//! key over out of band.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use anyhow::{Context, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use boring::nid::Nid;
use boring::pkey::{PKey, Public};
use boring::x509::X509;

use crate::config::ClientEntry;

/// One pre-registered client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    /// Operator-chosen label, used in logs.
    pub name: String,
    /// The canonical SubjectPublicKeyInfo DER this identity was matched by.
    ///
    /// Kept on the identity so a live connection can be rechecked against a
    /// replaced roster without re-parsing its certificate.
    pub key: Vec<u8>,
    /// Fixed IPv4 for this client's CONNECT-IP tunnels, if configured.
    pub ipv4: Option<Ipv4Addr>,
    /// Fixed IPv6 for this client's CONNECT-IP tunnels, if configured.
    pub ipv6: Option<Ipv6Addr>,
}

impl ClientIdentity {
    /// The fixed addresses this client is pinned to, in no particular order.
    pub fn static_addresses(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.ipv4
            .map(IpAddr::V4)
            .into_iter()
            .chain(self.ipv6.map(IpAddr::V6))
    }

    /// Whether any address is pinned, i.e. whether the address pool should be
    /// bypassed for this client.
    pub fn has_static_addresses(&self) -> bool {
        self.ipv4.is_some() || self.ipv6.is_some()
    }
}

/// The configured clients, indexed by public key.
#[derive(Debug, Default)]
pub struct ClientRegistry {
    /// Keyed by canonical SubjectPublicKeyInfo DER.
    ///
    /// Both the roster and the presented certificate are re-encoded through
    /// BoringSSL before they reach this map, so a key written as PEM matches
    /// the same key written as base64 DER, and a non-canonical encoding on the
    /// wire cannot dodge a lookup.
    by_spki: HashMap<Vec<u8>, Arc<ClientIdentity>>,
}

impl ClientRegistry {
    /// Build the registry from the `[[clients]]` tables.
    ///
    /// Every problem here is a configuration mistake that would otherwise show
    /// up as an unexplained handshake failure, so all of them are fatal.
    pub fn from_config(entries: &[ClientEntry]) -> anyhow::Result<Self> {
        let mut by_spki: HashMap<Vec<u8>, Arc<ClientIdentity>> =
            HashMap::with_capacity(entries.len());

        for (position, entry) in entries.iter().enumerate() {
            // Fall back to the position so every diagnostic can name the entry
            // even before the operator has labelled it.
            let label = if entry.name.is_empty() {
                format!("clients[{position}]")
            } else {
                entry.name.clone()
            };

            let spki = parse_public_key(&entry.public_key)
                .with_context(|| format!("client {label}: invalid public_key"))?;

            let ipv4 = entry
                .ipv4
                .as_deref()
                .map(|text| {
                    text.parse::<Ipv4Addr>()
                        .with_context(|| format!("client {label}: invalid ipv4 {text:?}"))
                })
                .transpose()?;
            let ipv6 = entry
                .ipv6
                .as_deref()
                .map(|text| {
                    text.parse::<Ipv6Addr>()
                        .with_context(|| format!("client {label}: invalid ipv6 {text:?}"))
                })
                .transpose()?;

            let identity = Arc::new(ClientIdentity {
                name: label.clone(),
                key: spki.clone(),
                ipv4,
                ipv6,
            });

            // Two entries sharing a key means one of them can never be
            // selected, and which one wins would come down to file order.
            if let Some(existing) = by_spki.insert(spki, identity) {
                bail!(
                    "clients {} and {label} share the same public_key",
                    existing.name
                );
            }
        }

        // A fixed address handed to two clients would make the routing table
        // hand one client's traffic to the other.
        let mut seen: HashMap<IpAddr, &str> = HashMap::new();
        for identity in by_spki.values() {
            for addr in identity.static_addresses() {
                if let Some(other) = seen.insert(addr, &identity.name) {
                    bail!(
                        "clients {other} and {} are both pinned to {addr}",
                        identity.name
                    );
                }
            }
        }

        Ok(Self { by_spki })
    }

    pub fn is_empty(&self) -> bool {
        self.by_spki.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_spki.len()
    }

    /// Look an identity up by the key it was matched on.
    ///
    /// Used to recheck a live connection after the roster is replaced: an
    /// identity that is gone, or that no longer matches the entry the
    /// connection was admitted under, must not keep its tunnel.
    pub fn lookup_key(&self, key: &[u8]) -> Option<&Arc<ClientIdentity>> {
        self.by_spki.get(key)
    }

    /// Whether `identity` is still current, i.e. present and unchanged.
    pub fn still_authorizes(&self, identity: &ClientIdentity) -> bool {
        self.lookup_key(&identity.key)
            .is_some_and(|current| **current == *identity)
    }

    /// Every fixed address across the roster.
    pub fn static_addresses(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.by_spki
            .values()
            .flat_map(|identity| identity.static_addresses())
    }

    /// Every fixed address together with the public key allowed to claim it.
    pub fn static_reservations(&self) -> impl Iterator<Item = (IpAddr, &[u8])> + '_ {
        self.by_spki.values().flat_map(|identity| {
            identity
                .static_addresses()
                .map(move |addr| (addr, identity.key.as_slice()))
        })
    }

    /// Resolve a presented certificate to a configured client.
    ///
    /// Only the key matters: the certificate is self-signed with an empty
    /// subject and a fresh serial per connection, so its chain, validity, and
    /// name carry no information worth checking.
    pub fn identify(&self, cert_der: &[u8]) -> Result<Arc<ClientIdentity>, IdentityError> {
        let spki = spki_from_cert_der(cert_der).map_err(|_| IdentityError::MalformedCertificate)?;
        match self.by_spki.get(&spki) {
            Some(identity) => Ok(Arc::clone(identity)),
            // Hand back the key so the operator can paste it straight into a
            // `[[clients]]` entry instead of reverse-engineering it.
            None => Err(IdentityError::UnknownKey(STANDARD.encode(&spki))),
        }
    }
}

/// A roster that can be replaced while the server is running.
///
/// Revoking a client would otherwise mean restarting the process, which drops
/// every other client's tunnel to remove one. Reads happen once per handshake
/// rather than per packet, so an `RwLock` is cheap enough and avoids a
/// dependency for the same effect.
#[derive(Debug)]
pub struct SharedRoster {
    current: RwLock<Arc<ClientRegistry>>,
    /// Bumped on every replacement.
    ///
    /// Event loops compare this against the generation they last acted on, so
    /// a reload costs one atomic read per sweep rather than a rescan.
    generation: AtomicU64,
}

impl Default for SharedRoster {
    fn default() -> Self {
        Self::new(ClientRegistry::default())
    }
}

impl SharedRoster {
    pub fn new(registry: ClientRegistry) -> Self {
        Self {
            current: RwLock::new(Arc::new(registry)),
            generation: AtomicU64::new(0),
        }
    }

    /// The roster in force right now.
    pub fn load(&self) -> Arc<ClientRegistry> {
        Arc::clone(&self.current.read().expect("roster poisoned"))
    }

    /// Install a new roster, returning its generation.
    pub fn replace(&self, registry: ClientRegistry) -> u64 {
        *self.current.write().expect("roster poisoned") = Arc::new(registry);
        // Released after the write, so an event loop that observes the new
        // generation is guaranteed to read the new roster.
        self.generation.fetch_add(1, Ordering::Release) + 1
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

/// Why a presented client certificate was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// The certificate did not parse, or its key is not a supported type.
    MalformedCertificate,
    /// A well-formed key that is not in the roster. Carries the base64 SPKI so
    /// it can be logged for enrollment.
    UnknownKey(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityError::MalformedCertificate => {
                write!(
                    f,
                    "client certificate is malformed or uses an unsupported key"
                )
            }
            IdentityError::UnknownKey(key) => {
                write!(f, "client public key is not registered: {key}")
            }
        }
    }
}

impl std::error::Error for IdentityError {}

/// Extract the canonical SubjectPublicKeyInfo DER from a certificate.
pub fn spki_from_cert_der(cert_der: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cert = X509::from_der(cert_der).context("certificate is not valid DER")?;
    let key = cert.public_key().context("certificate has no public key")?;
    canonical_spki(&key)
}

/// Parse a roster `public_key` value: base64 SPKI DER, or a PEM public key.
///
/// Both forms show up in practice — vendor APIs exchange the base64 DER, while
/// `openssl x509 -pubkey` prints PEM — and telling them apart is unambiguous.
pub fn parse_public_key(text: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        bail!("public key is empty");
    }

    let key = if trimmed.contains("-----BEGIN") {
        PKey::public_key_from_pem(trimmed.as_bytes()).context("not a valid PEM public key")?
    } else {
        // Tolerate the line breaks that survive a copy/paste out of JSON.
        let compact: String = trimmed
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let der = STANDARD
            .decode(&compact)
            .context("not valid base64 (expected SubjectPublicKeyInfo DER or a PEM block)")?;
        PKey::public_key_from_der(&der).context("not a valid SubjectPublicKeyInfo DER key")?
    };

    canonical_spki(&key)
}

/// Re-encode a public key to its canonical SPKI DER, rejecting key types no
/// known client uses.
fn canonical_spki(key: &PKey<Public>) -> anyhow::Result<Vec<u8>> {
    // MASQUE clients in this family use secp256r1 exclusively, and accepting
    // anything else would mean advertising support we cannot test.
    let ec = key
        .ec_key()
        .context("public key is not ECDSA (expected secp256r1 / P-256)")?;
    match ec.group().curve_name() {
        Some(Nid::X9_62_PRIME256V1) => {}
        other => bail!(
            "public key uses an unsupported curve {:?} (expected secp256r1 / P-256)",
            other.map_or("unknown", |nid| nid.short_name().unwrap_or("unknown"))
        ),
    }

    key.public_key_to_der()
        .context("failed to encode public key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::asn1::Asn1Time;
    use boring::bn::BigNum;
    use boring::ec::{EcGroup, EcKey};
    use boring::hash::MessageDigest;
    use boring::pkey::Private;
    use boring::x509::X509Builder;

    fn p256_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    fn public_key_b64(key: &PKey<Private>) -> String {
        STANDARD.encode(key.public_key_to_der().unwrap())
    }

    /// A stand-in for what these clients present: self-signed, empty subject,
    /// serial 0, short validity.
    fn self_signed_der(key: &PKey<Private>) -> Vec<u8> {
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&BigNum::from_u32(0).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        builder.set_pubkey(key).unwrap();
        builder.sign(key, MessageDigest::sha256()).unwrap();
        builder.build().to_der().unwrap()
    }

    fn entry(name: &str, public_key: String) -> ClientEntry {
        ClientEntry {
            name: name.into(),
            public_key,
            ipv4: None,
            ipv6: None,
        }
    }

    #[test]
    fn identifies_a_registered_key_from_a_self_signed_certificate() {
        let key = p256_key();
        let registry =
            ClientRegistry::from_config(&[entry("laptop", public_key_b64(&key))]).unwrap();

        let identity = registry.identify(&self_signed_der(&key)).unwrap();
        assert_eq!(identity.name, "laptop");
    }

    #[test]
    fn pem_and_base64_der_spellings_of_one_key_are_the_same_identity() {
        let key = p256_key();
        let pem = String::from_utf8(key.public_key_to_pem().unwrap()).unwrap();

        let from_pem = ClientRegistry::from_config(&[entry("a", pem)]).unwrap();
        let from_der = ClientRegistry::from_config(&[entry("a", public_key_b64(&key))]).unwrap();

        let cert = self_signed_der(&key);
        assert!(from_pem.identify(&cert).is_ok());
        assert!(from_der.identify(&cert).is_ok());
    }

    #[test]
    fn base64_with_embedded_newlines_still_parses() {
        let key = p256_key();
        let wrapped = public_key_b64(&key)
            .as_bytes()
            .chunks(24)
            .map(|chunk| String::from_utf8(chunk.to_vec()).unwrap())
            .collect::<Vec<_>>()
            .join("\n");

        let registry = ClientRegistry::from_config(&[entry("a", wrapped)]).unwrap();
        assert!(registry.identify(&self_signed_der(&key)).is_ok());
    }

    #[test]
    fn unregistered_key_is_reported_with_its_encoding() {
        let registered = p256_key();
        let stranger = p256_key();
        let registry =
            ClientRegistry::from_config(&[entry("known", public_key_b64(&registered))]).unwrap();

        match registry.identify(&self_signed_der(&stranger)) {
            // The reported key has to be directly pasteable into the roster.
            Err(IdentityError::UnknownKey(key)) => {
                assert_eq!(key, public_key_b64(&stranger));
            }
            other => panic!("expected an unknown-key rejection, got {other:?}"),
        }
    }

    #[test]
    fn malformed_certificate_is_rejected() {
        let registry =
            ClientRegistry::from_config(&[entry("a", public_key_b64(&p256_key()))]).unwrap();
        assert_eq!(
            registry.identify(b"not a certificate"),
            Err(IdentityError::MalformedCertificate)
        );
    }

    #[test]
    fn empty_registry_accepts_nobody() {
        let registry = ClientRegistry::default();
        assert!(registry.is_empty());
        assert!(registry.identify(&self_signed_der(&p256_key())).is_err());
    }

    #[test]
    fn rejects_non_p256_keys() {
        let rsa = PKey::from_rsa(boring::rsa::Rsa::generate(2048).unwrap()).unwrap();
        let spki = STANDARD.encode(rsa.public_key_to_der().unwrap());
        let error = ClientRegistry::from_config(&[entry("a", spki)]).unwrap_err();
        assert!(format!("{error:#}").contains("P-256"), "{error:#}");

        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let p384 = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let spki = STANDARD.encode(p384.public_key_to_der().unwrap());
        let error = ClientRegistry::from_config(&[entry("b", spki)]).unwrap_err();
        assert!(format!("{error:#}").contains("secp256r1"), "{error:#}");
    }

    #[test]
    fn rejects_malformed_roster_entries() {
        assert!(ClientRegistry::from_config(&[entry("a", String::new())]).is_err());
        assert!(ClientRegistry::from_config(&[entry("a", "!!not base64!!".into())]).is_err());

        let key = p256_key();
        let bad_ipv4 = ClientEntry {
            name: "a".into(),
            public_key: public_key_b64(&key),
            ipv4: Some("10.89.0.999".into()),
            ipv6: None,
        };
        assert!(ClientRegistry::from_config(&[bad_ipv4]).is_err());
    }

    #[test]
    fn rejects_duplicate_keys_and_duplicate_pinned_addresses() {
        let key = p256_key();
        let duplicate = [
            entry("a", public_key_b64(&key)),
            entry("b", public_key_b64(&key)),
        ];
        let error = ClientRegistry::from_config(&duplicate).unwrap_err();
        assert!(
            format!("{error:#}").contains("same public_key"),
            "{error:#}"
        );

        let pinned = |name: &str, key: &PKey<Private>| ClientEntry {
            name: name.into(),
            public_key: public_key_b64(key),
            ipv4: Some("10.89.0.2".into()),
            ipv6: None,
        };
        let clash = [pinned("a", &p256_key()), pinned("b", &p256_key())];
        let error = ClientRegistry::from_config(&clash).unwrap_err();
        assert!(format!("{error:#}").contains("pinned to"), "{error:#}");
    }

    #[test]
    fn unnamed_entries_are_labelled_by_position() {
        let error = ClientRegistry::from_config(&[entry("", "!!bad!!".into())]).unwrap_err();
        assert!(format!("{error:#}").contains("clients[0]"), "{error:#}");
    }

    #[test]
    fn static_addresses_are_collected_across_the_roster() {
        let clients = [
            ClientEntry {
                name: "a".into(),
                public_key: public_key_b64(&p256_key()),
                ipv4: Some("10.89.0.2".into()),
                ipv6: Some("fd00:abcd::2".into()),
            },
            entry("b", public_key_b64(&p256_key())),
        ];
        let registry = ClientRegistry::from_config(&clients).unwrap();
        assert_eq!(registry.len(), 2);

        let mut addrs: Vec<IpAddr> = registry.static_addresses().collect();
        addrs.sort();
        assert_eq!(
            addrs,
            vec![
                "10.89.0.2".parse::<IpAddr>().unwrap(),
                "fd00:abcd::2".parse::<IpAddr>().unwrap(),
            ]
        );
    }
}
