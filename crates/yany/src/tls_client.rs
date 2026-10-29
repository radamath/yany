use anyhow::{bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

#[derive(Debug)]
struct FingerprintPin {
    expected: Option<String>,
    seen: Mutex<Option<String>>,
}

impl ServerCertVerifier for FingerprintPin {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let got = format!("{}", blake3::hash(end_entity.as_ref()));
        if let Some(expected) = &self.expected {
            if !ct_eq_hex(&got, expected) {
                return Err(TlsError::General(format!(
                    "tls fingerprint mismatch got={got} expected={expected}"
                )));
            }
        }
        if let Ok(mut slot) = self.seen.lock() {
            *slot = Some(got);
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub async fn connect(
    addr: &str,
    fingerprint: &str,
) -> Result<TlsStream<TcpStream>> {
    Ok(connect_tofu(addr, Some(fingerprint)).await?.0)
}

pub async fn connect_tofu(
    addr: &str,
    fingerprint: Option<&str>,
) -> Result<(TlsStream<TcpStream>, String)> {
    let expected = fingerprint
        .map(normalize_fingerprint)
        .transpose()?;
    let pin = Arc::new(FingerprintPin {
        expected,
        seen: Mutex::new(None),
    });
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(pin.clone())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"yany/1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connect {addr}"))?;
    stream.set_nodelay(true)?;
    let name = sni_name(addr)?;
    let tls = connector.connect(name, stream).await?;
    let seen = pin
        .seen
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .ok_or_else(|| anyhow::anyhow!("tls fingerprint missing after handshake"))?;
    Ok((tls, seen))
}

fn normalize_fingerprint(fingerprint: &str) -> Result<String> {
    let expected: String = fingerprint
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_lowercase();
    if expected.len() != 64 {
        bail!("TLS fingerprint must be the full 64 hex chars printed by yany-relay");
    }
    Ok(expected)
}

fn sni_name(addr: &str) -> Result<ServerName<'static>> {
    let host = addr
        .rsplit_once(':')
        .map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']'))
        .unwrap_or(addr);
    let label = if host.parse::<std::net::IpAddr>().is_ok() {
        "yany-relay"
    } else {
        host
    };
    ServerName::try_from(label.to_string()).map_err(|_| anyhow::anyhow!("server name {label}"))
}

fn ct_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
