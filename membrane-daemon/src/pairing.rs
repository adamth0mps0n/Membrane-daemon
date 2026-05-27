//! Daemon-side pairing logic.
//!
//! v1 is stub-pairing: instead of an HTTP exchange with a real cloud,
//! the customer obtains a pairing token out-of-band (operator hands it
//! over) and feeds it to `membrane-daemon pair --token <T>`.
//!
//! Steps:
//!
//! 1. Generate a fresh keypair if one isn't on disk (or reuse if present
//!    and the customer wants to re-pair without rotating the key).
//! 2. Build a CSR for that public key.
//! 3. Print the CSR for the customer to send to the operator. (In real
//!    pairing this step is a browser-mediated POST; for the stub it's
//!    "copy this blob and paste it into stub-issuer".)
//! 4. When a token arrives, decode it, install:
//!    - signed daemon cert at `cert_path()`
//!    - cloud cert pin at `cloud_pin_path()`
//!    - endpoint into `policy.toml`
//!
//! Token format: base64-encoded JSON, well-formed today, can be
//! upgraded to a more compact framing later without breaking the CLI.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use rcgen::{CertificateParams, CertificateSigningRequestParams, KeyPair};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::config::Config;

/// A pairing token. Issued by the cloud (or stub-issuer); consumed by
/// the daemon's `pair` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingToken {
    /// Token format version. Bump on incompatible changes.
    pub v: u32,
    /// PEM of the daemon's signed cert chain (leaf + any intermediates).
    pub daemon_cert_pem: String,
    /// Hex-encoded Blake3 of the cloud's serving cert DER. The daemon
    /// pins this so a future cloud cert rotation can't silently MITM.
    pub cloud_pin_hex: String,
    /// Endpoint URL the daemon should dial.
    pub endpoint: String,
    /// Customer label for audit log display (optional).
    pub customer_label: Option<String>,
}

impl PairingToken {
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&json))
    }
    pub fn decode(token: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.trim()).context("base64 decode")?;
        let t: PairingToken = serde_json::from_slice(&bytes)
            .context("token JSON decode")?;
        if t.v != 1 { bail!("unsupported token version {}", t.v); }
        if t.daemon_cert_pem.is_empty() { bail!("token missing daemon cert"); }
        if t.cloud_pin_hex.is_empty() { bail!("token missing cloud pin"); }
        if t.endpoint.is_empty() { bail!("token missing endpoint"); }
        Ok(t)
    }
}

/// Ensure a daemon keypair exists on disk. If `key_path` exists,
/// load it; otherwise generate a fresh one and write it.
///
/// Returns the loaded/generated key pair plus a flag indicating whether
/// a new key was generated (so the caller can warn that any existing
/// cert is now invalid).
pub fn ensure_keypair(key_path: &Path) -> Result<(KeyPair, bool)> {
    if key_path.exists() {
        let pem = std::fs::read_to_string(key_path).context("read existing key")?;
        let kp = KeyPair::from_pem(&pem).context("parse existing key PEM")?;
        return Ok((kp, false));
    }
    let kp = KeyPair::generate().context("generate keypair")?;
    if let Some(parent) = key_path.parent() { std::fs::create_dir_all(parent)?; }
    std::fs::write(key_path, kp.serialize_pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::fs::metadata(key_path)?.permissions();
        p.set_mode(0o600);
        std::fs::set_permissions(key_path, p)?;
    }
    Ok((kp, true))
}

/// Build a CSR (PEM) for the given keypair. The customer sends this PEM
/// to the operator/cloud; the cloud responds with a PairingToken.
///
/// CN = "membrane-daemon"; the cloud determines what subject info ends
/// up in the signed cert, so what we set here is mostly decorative.
pub fn build_csr(key_pair: &KeyPair) -> Result<String> {
    let mut params = CertificateParams::new(vec!["membrane-daemon".into()])
        .context("CSR params")?;
    params.distinguished_name.push(rcgen::DnType::CommonName, "membrane-daemon");
    let csr = params.serialize_request(key_pair).context("build CSR")?;
    Ok(csr.pem().context("CSR to PEM")?)
}

/// Install a pairing token: writes the daemon cert, the cloud pin, and
/// updates policy.toml with the endpoint. The daemon's private key must
/// already exist (created by `ensure_keypair` before the CSR was sent).
///
/// Returns the previous endpoint if it was changed (for audit display).
pub fn install_token(
    token: &PairingToken,
    cfg: &Config,
    cert_path: &Path,
    pin_path: &Path,
) -> Result<Option<String>> {
    // Validate the daemon cert is a parseable cert.
    let _ = rustls_pemfile::certs(&mut token.daemon_cert_pem.as_bytes())
        .next().ok_or_else(|| anyhow!("token cert PEM contains no certificate"))?
        .context("parse daemon cert PEM")?;
    // Validate the cloud pin is hex.
    if !token.cloud_pin_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("cloud pin is not hex");
    }
    if token.cloud_pin_hex.len() != 64 {
        bail!("cloud pin is not 32 bytes (got {} hex chars; expected 64)",
            token.cloud_pin_hex.len());
    }

    // Write atomically: temp file + rename.
    write_atomic(cert_path, token.daemon_cert_pem.as_bytes())
        .context("write daemon cert")?;
    write_atomic(pin_path, token.cloud_pin_hex.as_bytes())
        .context("write cloud pin")?;

    // Update policy.toml endpoint.
    let mut new_cfg = cfg.clone();
    let prev = if new_cfg.endpoint != token.endpoint {
        Some(std::mem::replace(&mut new_cfg.endpoint, token.endpoint.clone()))
    } else { None };
    new_cfg.save_user().context("save updated policy.toml")?;
    Ok(prev)
}

fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
    let mut tmp = tempfile::NamedTempFile::new_in(
        path.parent().unwrap_or_else(|| Path::new(".")),
    )?;
    use std::io::Write;
    tmp.write_all(data)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Sign a CSR with the given issuer cert and key. Used by `stub-issuer`
/// to mint daemon certs; exposed here so the same logic can be reused
/// in real-cloud server code later.
///
/// `csr_pem` — PEM-encoded CSR from the daemon.
/// `issuer_cert_pem` — PEM of the cloud's CA cert.
/// `issuer_key_pem` — PEM of the cloud's CA key.
///
/// Returns the signed daemon cert as PEM.
pub fn sign_csr(
    csr_pem: &str,
    issuer_cert_pem: &str,
    issuer_key_pem: &str,
) -> Result<String> {
    let csr = CertificateSigningRequestParams::from_pem(csr_pem)
        .context("parse CSR PEM")?;
    let issuer_key = KeyPair::from_pem(issuer_key_pem)
        .context("parse issuer key PEM")?;
    let issuer_cert_params = CertificateParams::from_ca_cert_pem(issuer_cert_pem)
        .context("parse issuer cert PEM")?;
    let issuer_cert = issuer_cert_params.self_signed(&issuer_key)
        .context("rebuild issuer cert")?;
    let signed = csr.signed_by(&issuer_cert, &issuer_key)
        .context("sign CSR")?;
    Ok(signed.pem())
}

/// Compute the pin (hex Blake3) of a cert's DER bytes. The stub issuer
/// uses this to derive the cloud_pin_hex field from the cloud's serving
/// cert. The daemon's PinnedVerifier computes the same hash and compares.
pub fn pin_hex(cert_der: &[u8]) -> String {
    let digest = blake3::hash(cert_der);
    let mut out = String::with_capacity(64);
    for b in digest.as_bytes() {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn ca_pair() -> (String, String, Vec<u8>) {
        let mut params = CertificateParams::new(vec!["test-issuer".into()]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "test-issuer");
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem(), cert.der().to_vec())
    }

    #[test]
    fn token_round_trip() {
        let t = PairingToken {
            v: 1,
            daemon_cert_pem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".into(),
            cloud_pin_hex: "0".repeat(64),
            endpoint: "https://cloud.example.com:443".into(),
            customer_label: Some("acme corp".into()),
        };
        let encoded = t.encode().unwrap();
        let decoded = PairingToken::decode(&encoded).unwrap();
        assert_eq!(decoded.endpoint, t.endpoint);
        assert_eq!(decoded.customer_label, t.customer_label);
    }

    #[test]
    fn token_rejects_unknown_version() {
        let mut t = PairingToken {
            v: 99,
            daemon_cert_pem: "x".into(),
            cloud_pin_hex: "0".repeat(64),
            endpoint: "x".into(),
            customer_label: None,
        };
        // Fields are still present; decoder should reject by version first.
        t.daemon_cert_pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".into();
        let encoded = t.encode().unwrap();
        assert!(PairingToken::decode(&encoded).is_err());
    }

    #[test]
    fn token_rejects_missing_fields() {
        // Empty pin should fail.
        let t = PairingToken {
            v: 1,
            daemon_cert_pem: "abc".into(),
            cloud_pin_hex: "".into(),
            endpoint: "x".into(),
            customer_label: None,
        };
        let encoded = t.encode().unwrap();
        assert!(PairingToken::decode(&encoded).is_err());
    }

    #[test]
    fn keypair_is_created_then_reused() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("daemon.key");
        let (kp1, new1) = ensure_keypair(&key_path).unwrap();
        assert!(new1, "first call should generate");
        let pem1 = kp1.serialize_pem();

        let (kp2, new2) = ensure_keypair(&key_path).unwrap();
        assert!(!new2, "second call should reuse");
        assert_eq!(pem1, kp2.serialize_pem());
    }

    #[test]
    fn csr_signs_with_ca_and_validates_pem() {
        let (ca_pem, ca_key_pem, _) = ca_pair();
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("daemon.key");
        let (kp, _) = ensure_keypair(&key_path).unwrap();
        let csr_pem = build_csr(&kp).unwrap();
        assert!(csr_pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));

        let signed = sign_csr(&csr_pem, &ca_pem, &ca_key_pem).unwrap();
        assert!(signed.starts_with("-----BEGIN CERTIFICATE-----"));
        // Round-trip via rustls's PEM parser to confirm it's a valid cert.
        let parsed: Vec<_> = rustls_pemfile::certs(&mut signed.as_bytes())
            .collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(parsed.len(), 1, "should parse exactly one cert");
    }

    #[test]
    fn pin_hex_is_64_chars_lowercase() {
        let h = pin_hex(b"some cert bytes");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase())));
    }

    #[test]
    #[serial]
    fn install_token_writes_cert_pin_and_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("daemon.crt");
        let pin_path = dir.path().join("cloud.pin");
        std::env::set_var("HOME", dir.path()); // for cfg.save_user()

        let (ca_pem, ca_key_pem, ca_der) = ca_pair();
        let key_path = dir.path().join("daemon.key");
        let (kp, _) = ensure_keypair(&key_path).unwrap();
        let csr = build_csr(&kp).unwrap();
        let signed_cert = sign_csr(&csr, &ca_pem, &ca_key_pem).unwrap();

        let token = PairingToken {
            v: 1,
            daemon_cert_pem: signed_cert,
            cloud_pin_hex: pin_hex(&ca_der),
            endpoint: "https://new-cloud.example.com:443".into(),
            customer_label: Some("tester".into()),
        };

        let cfg = Config::default();
        let prev = install_token(&token, &cfg, &cert_path, &pin_path).unwrap();
        assert!(prev.is_some(), "endpoint changed; previous should be reported");

        assert!(cert_path.exists());
        assert!(pin_path.exists());
        let pin_on_disk = std::fs::read_to_string(&pin_path).unwrap();
        assert_eq!(pin_on_disk, token.cloud_pin_hex);
    }

    #[test]
    #[serial]
    fn install_token_rejects_bad_pin() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", dir.path());
        let (ca_pem, ca_key_pem, _) = ca_pair();
        let key_path = dir.path().join("daemon.key");
        let (kp, _) = ensure_keypair(&key_path).unwrap();
        let csr = build_csr(&kp).unwrap();
        let signed_cert = sign_csr(&csr, &ca_pem, &ca_key_pem).unwrap();

        let bad = PairingToken {
            v: 1,
            daemon_cert_pem: signed_cert,
            cloud_pin_hex: "not-hex-and-too-short".into(),
            endpoint: "x".into(),
            customer_label: None,
        };
        let result = install_token(&bad, &Config::default(),
            &dir.path().join("c"), &dir.path().join("p"));
        assert!(result.is_err());
    }
}
