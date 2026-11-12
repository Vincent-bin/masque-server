use anyhow::Result;
use boring::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    x509::{X509, X509NameBuilder, extension::SubjectAlternativeName},
};
use std::{fs, path::PathBuf};

/// A fresh loopback-only test identity. No credentials are stored in the repo.
pub struct Identity {
    pub cert: PathBuf,
    pub key: PathBuf,
    _directory: tempfile::TempDir,
}

impl Identity {
    pub fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "localhost")?;
        let name = name.build();
        let mut serial = BigNum::new()?;
        serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
        let mut cert = X509::builder()?;
        cert.set_version(2)?;
        cert.set_serial_number(serial.to_asn1_integer()?.as_ref())?;
        cert.set_subject_name(&name)?;
        cert.set_issuer_name(&name)?;
        cert.set_pubkey(&key)?;
        cert.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        cert.set_not_after(Asn1Time::days_from_now(1)?.as_ref())?;
        let san = SubjectAlternativeName::new()
            .dns("localhost")
            .build(&cert.x509v3_context(None, None))?;
        cert.append_extension(san)?;
        cert.sign(&key, MessageDigest::sha256())?;
        let cert_path = directory.path().join("certificate.pem");
        let key_path = directory.path().join("key.pem");
        fs::write(&cert_path, cert.build().to_pem()?)?;
        fs::write(&key_path, key.private_key_to_pem_pkcs8()?)?;
        Ok(Self {
            cert: cert_path,
            key: key_path,
            _directory: directory,
        })
    }
}
