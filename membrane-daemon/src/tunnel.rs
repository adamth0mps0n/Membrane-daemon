//! QUIC + mTLS tunnel from the daemon out to the cloud.
//!
//! The daemon is the QUIC *client* — it dials the cloud, presenting
//! its own certificate (issued during pairing). The cloud presents its
//! cert which the daemon verifies via pinning (we don't have a CA for
//! v1; the cloud's cert hash lives in `cloud.pin`).
//!
//! Per RPC: the cloud opens a bidirectional QUIC stream, sends one
//! length-prefixed Request, and reads one length-prefixed Response.
//! The daemon spawns a task per incoming stream; many RPCs run in
//! parallel.
//!
//! Reconnect: exponential backoff on connection failure, capped at
//! 60 seconds between attempts. Backoff resets on a successful
//! handshake.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    DigitallySignedStruct,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    SignatureScheme,
};
use crate::audit::Audit;
use crate::config::Config;
use crate::handlers;

/// Dial the cloud and serve RPCs forever (with reconnect on failure).
/// Returns only if cancelled or on an unrecoverable error.
pub async fn run(cfg: Config, audit: Audit) -> Result<()> {
    let cert_path = crate::paths::cert_path();
    let key_path = crate::paths::key_path();
    let pin_path = crate::paths::cloud_pin_path();

    // Production: cert + key + cloud pin must all exist. The pairing flow
    // (`membrane-daemon pair`) is what creates them. We fail-closed here
    // rather than silently generating a self-signed cert, because the
    // latter produces a working-looking connection to no one useful.
    //
    // The `dev-cert` feature flag (test/integration only) reopens the
    // old self-signed + unpinned path. It must not be enabled in
    // release builds.
    #[cfg(feature = "dev-cert")]
    ensure_dev_cert(&cert_path, &key_path)
        .context("ensure daemon cert+key")?;

    if !cert_path.exists() || !key_path.exists() {
        anyhow::bail!(
            "daemon not paired: missing cert at {} or key at {}. \
             Run `membrane-daemon pair` to generate a CSR, send it to \
             your operator, then run `membrane-daemon pair --token <T>` \
             to install the returned token.",
            cert_path.display(), key_path.display()
        );
    }
    if !pin_path.exists() {
        // We allow the feature flag to relax this for integration tests
        // against mock-cloud; production builds enforce it.
        #[cfg(not(feature = "dev-cert"))]
        anyhow::bail!(
            "daemon not paired: cloud pin missing at {}. \
             A valid pairing token installs this. If you have a token, \
             run `membrane-daemon pair --token <T>`.",
            pin_path.display()
        );
    }

    let cloud_pin = if pin_path.exists() {
        Some(std::fs::read(&pin_path).context("read cloud pin")?)
    } else {
        None
    };

    let client_cfg = build_client_config(&cert_path, &key_path, cloud_pin.as_deref())?;
    let bind: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut endpoint = Endpoint::client(bind).context("bind QUIC endpoint")?;
    endpoint.set_default_client_config(client_cfg);

    let mut backoff_secs = 1u64;
    let cfg = Arc::new(cfg);
    let audit = Arc::new(audit);

    loop {
        let (host, port) = parse_endpoint(&cfg.endpoint)?;
        let addr = resolve(&host, port)
            .with_context(|| format!("resolve {host}:{port}"))?;
        tracing::info!("dialing cloud at {addr} ({host})");

        let connecting = match endpoint.connect(addr, &host) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("connect setup failed: {e}; backing off {backoff_secs}s");
                let _ = audit.write(crate::audit::Event::Lifecycle {
                    event: "connect_failed".into(),
                    detail: e.to_string(),
                });
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
                continue;
            }
        };

        let conn = match connecting.await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("connection failed: {e}; backing off {backoff_secs}s");
                let _ = audit.write(crate::audit::Event::Lifecycle {
                    event: "connect_failed".into(),
                    detail: e.to_string(),
                });
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
                continue;
            }
        };

        tracing::info!("connected; serving RPCs");
        let _ = audit.write(crate::audit::Event::Lifecycle {
            event: "connected".into(),
            detail: format!("remote={addr}"),
        });
        backoff_secs = 1;

        if let Err(e) = serve_streams(&conn, cfg.clone(), audit.clone()).await {
            tracing::warn!("connection ended: {e}");
            let _ = audit.write(crate::audit::Event::Lifecycle {
                event: "disconnected".into(),
                detail: e.to_string(),
            });
        }
        // Loop back to redial.
    }
}

/// Accept bidirectional streams from the cloud and spawn one task per
/// RPC. Returns when the connection ends (idle, closed, or errored).
async fn serve_streams(
    conn: &quinn::Connection,
    cfg: Arc<Config>,
    audit: Arc<Audit>,
) -> Result<()> {
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::ConnectionClosed(_)) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let cfg = cfg.clone();
        let audit = audit.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, cfg, audit).await {
                tracing::warn!("stream handler error: {e}");
            }
        });
    }
}

/// One RPC: read length-prefixed Request, dispatch, write length-prefixed
/// Response, close.
async fn handle_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    cfg: Arc<Config>,
    audit: Arc<Audit>,
) -> Result<()> {
    // Read length prefix.
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await
        .map_err(|e| anyhow::anyhow!("read length prefix: {e}"))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 64 * 1024 * 1024 {
        anyhow::bail!("request too large: {len} bytes");
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await
        .map_err(|e| anyhow::anyhow!("read body: {e}"))?;

    let req: membrane_wire::Request = bincode::deserialize(&body)
        .context("decode request")?;

    // Handlers are sync (file IO, blocking exec). Run on a blocking
    // worker so the QUIC runtime stays responsive.
    let cfg2 = cfg.clone();
    let audit2 = audit.clone();
    let resp = tokio::task::spawn_blocking(move || {
        handlers::dispatch(req, &cfg2, &audit2)
    }).await.context("dispatch panicked")?;

    let frame = membrane_wire::encode(&resp).context("encode response")?;
    send.write_all(&frame).await
        .map_err(|e| anyhow::anyhow!("write response: {e}"))?;
    send.finish().context("finish send stream")?;
    Ok(())
}

// ── TLS configuration ──────────────────────────────────────────────

fn build_client_config(
    cert_path: &Path,
    key_path: &Path,
    cloud_pin: Option<&[u8]>,
) -> Result<ClientConfig> {
    let cert_chain = load_certs(cert_path).context("load daemon cert")?;
    let key = load_key(key_path).context("load daemon key")?;

    let verifier: Arc<dyn ServerCertVerifier> = match cloud_pin {
        Some(pin) => Arc::new(PinnedVerifier { pin: pin.to_vec() }),
        None => {
            // No pin on disk. `run()` rejects this in production builds;
            // it's only reachable when the `dev-cert` feature is on
            // (integration tests against mock-cloud).
            #[cfg(feature = "dev-cert")]
            { Arc::new(NoVerify) }
            #[cfg(not(feature = "dev-cert"))]
            { anyhow::bail!("cloud pin missing — daemon must be paired before connecting"); }
        }
    };

    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(cert_chain, key)
        .context("install client auth cert")?;

    let crypto: Arc<dyn quinn::crypto::ClientConfig> = Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .context("rustls -> quinn crypto")?,
    );
    let mut client_cfg = ClientConfig::new(crypto);

    // Configure idle timeout and keep-alive. quinn's defaults are
    // max_idle=30s and keepalive=disabled, which means a quiet daemon
    // (no RPCs in flight) gets disconnected every 30 seconds and
    // reconnects — wasteful churn that shows up in the audit log and
    // creates a brief window after each reconnect where the cloud
    // sees no agent.
    //
    // Pick a generous max_idle (5 minutes) and a keep-alive interval
    // that's well below half the idle timeout (60s) so we have at
    // least two opportunities to send a keep-alive frame before the
    // remote considers us idle.
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(300).try_into().expect("5 min idle"),
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(60)));
    client_cfg.transport_config(Arc::new(transport));
    Ok(client_cfg)
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = std::io::BufReader::new(std::fs::File::open(path)?);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    Ok(certs?)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(std::fs::File::open(path)?);
    let key = rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key in {}", path.display()))?;
    Ok(key)
}

/// Signature schemes both verifiers accept. Factored out so PinnedVerifier
/// doesn't have to instantiate a NoVerify just to copy the list.
fn supported_schemes() -> Vec<SignatureScheme> {
    use SignatureScheme::*;
    vec![
        ECDSA_NISTP256_SHA256, ECDSA_NISTP384_SHA384,
        RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512,
        RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
        ED25519,
    ]
}

/// Verifier that accepts any cert. ONLY available behind the `dev-cert`
/// feature flag for integration tests against mock-cloud. Production
/// daemons must use `PinnedVerifier` with a real cloud pin.
#[cfg(feature = "dev-cert")]
#[derive(Debug)]
struct NoVerify;

#[cfg(feature = "dev-cert")]
impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        supported_schemes()
    }
}

/// Verifier that accepts the cloud's cert only if its raw DER bytes
/// match the pinned hash on disk.
#[derive(Debug)]
struct PinnedVerifier { pin: Vec<u8> }

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let hash = pin_hash(end_entity.as_ref());
        // pin file stores the BLAKE3 of the cert's DER, base16-encoded.
        // For dev simplicity we accept either raw bytes or hex.
        let pin_bytes = match hex_decode(&self.pin) {
            Some(b) => b,
            None => self.pin.clone(),
        };
        if hash == pin_bytes {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "cloud cert pin mismatch: got {} bytes, expected {} bytes",
                hash.len(), pin_bytes.len()
            )))
        }
    }
    fn verify_tls12_signature(
        &self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        supported_schemes()
    }
}

/// Compute the Blake3 pin of a cert's DER bytes. 32 bytes raw; the
/// pin file on disk stores the hex form. Pinning is what binds the
/// daemon's view of "the cloud" to a specific serving certificate.
fn pin_hash(data: &[u8]) -> Vec<u8> {
    blake3::hash(data).as_bytes().to_vec()
}

fn hex_decode(s: &[u8]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(s).ok()?.trim();
    if s.len() % 2 != 0 { return None; }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

// ── Endpoint parsing ───────────────────────────────────────────────

fn parse_endpoint(endpoint: &str) -> Result<(String, u16)> {
    // Accept either "host:port" or "https://host:port".
    let stripped = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("quic://"))
        .unwrap_or(endpoint);
    let (host, port) = match stripped.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().context("port")?),
        None => (stripped.to_string(), 443),
    };
    Ok((host, port))
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    (host, port).to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no addresses for {host}:{port}"))
}

// ── Dev cert generation (test-only) ────────────────────────────────

/// Generate a self-signed cert+key for development/integration testing
/// against mock-cloud. ONLY available behind the `dev-cert` feature flag;
/// production daemons must use `membrane-daemon pair` to obtain a real
/// CA-signed cert.
#[cfg(feature = "dev-cert")]
fn ensure_dev_cert(cert_path: &Path, key_path: &Path) -> Result<()> {
    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }
    tracing::info!("generating self-signed dev cert at {}", cert_path.display());
    let cert = rcgen::generate_simple_self_signed(vec!["membrane-daemon-dev".into()])
        .context("generate self-signed cert")?;
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(cert_path, cert.cert.pem())?;
    std::fs::write(key_path, cert.key_pair.serialize_pem())?;
    // Permission tightening on the key file (Unix only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::fs::metadata(key_path)?.permissions();
        p.set_mode(0o600);
        std::fs::set_permissions(key_path, p)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_endpoint_with_scheme() {
        let (h, p) = parse_endpoint("https://cloud.example.com:8443").unwrap();
        assert_eq!(h, "cloud.example.com");
        assert_eq!(p, 8443);
    }

    #[test]
    fn parse_endpoint_bare() {
        let (h, p) = parse_endpoint("host:1234").unwrap();
        assert_eq!(h, "host");
        assert_eq!(p, 1234);
    }

    #[test]
    fn parse_endpoint_defaults_443() {
        let (_, p) = parse_endpoint("host").unwrap();
        assert_eq!(p, 443);
    }

    #[test]
    fn hex_decode_round_trip() {
        let bytes = vec![0x12u8, 0x34, 0xab, 0xcd, 0xef];
        let s: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let decoded = hex_decode(s.as_bytes()).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[cfg(feature = "dev-cert")]
    #[test]
    fn dev_cert_generated_on_first_call() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("daemon.crt");
        let key = dir.path().join("daemon.key");
        ensure_dev_cert(&cert, &key).unwrap();
        assert!(cert.exists());
        assert!(key.exists());
        let pem = std::fs::read_to_string(&cert).unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[cfg(feature = "dev-cert")]
    #[test]
    fn dev_cert_not_regenerated_if_present() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("daemon.crt");
        let key = dir.path().join("daemon.key");
        ensure_dev_cert(&cert, &key).unwrap();
        let first = std::fs::read(&cert).unwrap();
        ensure_dev_cert(&cert, &key).unwrap();
        let second = std::fs::read(&cert).unwrap();
        assert_eq!(first, second, "cert should not have been regenerated");
    }
}
