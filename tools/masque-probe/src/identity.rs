use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::ec::EcKey;
use boring::hash::MessageDigest;
use boring::pkey::{PKey, Private, Public};
use boring::x509::{X509, X509Builder};
use serde::Deserialize;
use zeroize::{Zeroize as _, Zeroizing};

use crate::report::ProbeFailure;

pub struct ClientIdentity {
    key: PKey<Private>,
    certificate: X509,
    pinned_server_key: PKey<Public>,
}

#[derive(Deserialize)]
struct EnrollmentJson {
    private_key: String,
    endpoint_pub_key: String,
}

impl ClientIdentity {
    pub fn from_enrollment(path: &Path) -> Result<Self, ProbeFailure> {
        let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|error| {
            ProbeFailure::new(
                "CLIENT_CONFIG_ERROR",
                format!("could not read {}: {error}", path.display()),
            )
        })?);
        let mut raw: EnrollmentJson = serde_json::from_str(&text).map_err(|error| {
            ProbeFailure::new(
                "CLIENT_CONFIG_ERROR",
                format!("{} is not an enrollment JSON file: {error}", path.display()),
            )
        })?;

        let result = (|| {
            let mut private_der =
                Zeroizing::new(STANDARD.decode(&raw.private_key).map_err(|error| {
                    ProbeFailure::new(
                        "CLIENT_CONFIG_ERROR",
                        format!("private_key is not base64 DER: {error}"),
                    )
                })?);
            let ec_key = EcKey::private_key_from_der(&private_der).map_err(|error| {
                ProbeFailure::new(
                    "CLIENT_CONFIG_ERROR",
                    format!("private_key is not a SEC1 EC key: {error}"),
                )
            })?;
            private_der.zeroize();
            let key = PKey::from_ec_key(ec_key).map_err(|error| {
                ProbeFailure::new(
                    "CLIENT_CONFIG_ERROR",
                    format!("could not load client key: {error}"),
                )
            })?;
            let pinned_server_key = PKey::public_key_from_pem(raw.endpoint_pub_key.as_bytes())
                .map_err(|error| {
                    ProbeFailure::new(
                        "CLIENT_CONFIG_ERROR",
                        format!("endpoint_pub_key is not a PEM public key: {error}"),
                    )
                })?;
            let certificate = self_signed_certificate(&key)?;
            Ok(Self {
                key,
                certificate,
                pinned_server_key,
            })
        })();

        raw.private_key.zeroize();
        raw.endpoint_pub_key.zeroize();
        result
    }

    pub fn configure_context(
        &self,
        builder: &mut boring::ssl::SslContextBuilder,
    ) -> Result<(), ProbeFailure> {
        builder.set_verify(boring::ssl::SslVerifyMode::NONE);
        builder
            .set_certificate(&self.certificate)
            .map_err(|error| ProbeFailure::new("CLIENT_CERT_ERROR", error.to_string()))?;
        builder
            .set_private_key(&self.key)
            .map_err(|error| ProbeFailure::new("CLIENT_CERT_ERROR", error.to_string()))?;
        builder
            .check_private_key()
            .map_err(|error| ProbeFailure::new("CLIENT_CERT_ERROR", error.to_string()))?;
        Ok(())
    }

    pub fn verify_peer_certificate(&self, der: &[u8]) -> Result<(), ProbeFailure> {
        let certificate = X509::from_der(der).map_err(|error| {
            ProbeFailure::new(
                "TLS_PIN_MISMATCH",
                format!("server certificate is not valid DER: {error}"),
            )
        })?;
        let key = certificate.public_key().map_err(|error| {
            ProbeFailure::new(
                "TLS_PIN_MISMATCH",
                format!("server certificate has no public key: {error}"),
            )
        })?;
        if !key.public_eq(&self.pinned_server_key) {
            return Err(ProbeFailure::new(
                "TLS_PIN_MISMATCH",
                "server certificate public key does not match endpoint_pub_key",
            ));
        }
        Ok(())
    }
}

fn self_signed_certificate(key: &PKey<Private>) -> Result<X509, ProbeFailure> {
    let mut builder = X509Builder::new()
        .map_err(|error| ProbeFailure::new("CLIENT_CERT_ERROR", error.to_string()))?;
    builder
        .set_version(2)
        .map_err(|error| ProbeFailure::new("CLIENT_CERT_ERROR", error.to_string()))?;
    let serial = BigNum::from_u32(0)
        .and_then(|value| value.to_asn1_integer())
        .map_err(|error| ProbeFailure::new("CLIENT_CERT_ERROR", error.to_string()))?;
    builder
        .set_serial_number(&serial)
        .map_err(|error| ProbeFailure::new("CLIENT_CERT_ERROR", error.to_string()))?;
    let not_before = Asn1Time::days_from_now(0)
        .map_err(|error| ProbeFailure::new("CLIENT_CERT_ERROR", error.to_string()))?;
    let not_after = Asn1Time::days_from_now(1)
        .map_err(|error| ProbeFailure::new("CLIENT_CERT_ERROR", error.to_string()))?;
    builder
        .set_not_before(&not_before)
        .and_then(|_| builder.set_not_after(&not_after))
        .and_then(|_| builder.set_pubkey(key))
        .and_then(|_| builder.sign(key, MessageDigest::sha256()))
        .map_err(|error| ProbeFailure::new("CLIENT_CERT_ERROR", error.to_string()))?;
    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::ec::{EcGroup, EcKey};
    use boring::nid::Nid;

    #[test]
    fn generated_certificate_contains_the_enrolled_key() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let certificate = self_signed_certificate(&key).unwrap();
        assert!(certificate.public_key().unwrap().public_eq(&key));
    }
}
