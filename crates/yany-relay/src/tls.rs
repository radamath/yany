use anyhow::{bail, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

pub fn acceptor_from_pem(cert: &Path, key: &Path) -> Result<TlsAcceptor> {
    let certs = load_certs(cert)?;
    let key = load_key(key)?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("tls cert/key")?;
    config.alpn_protocols = vec![b"yany/1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub fn load_or_create_dev_cert(dir: &Path) -> Result<(PathBuf, PathBuf, String)> {
    let cert_path = dir.join("dev-cert.pem");
    let key_path = dir.join("dev-key.pem");
    if cert_path.is_file() && key_path.is_file() {
        let fp = fingerprint_file(&cert_path)?;
        return Ok((cert_path, key_path, fp));
    }
    generate_dev_cert(dir)
}

pub fn fingerprint_file(cert: &Path) -> Result<String> {
    let certs = load_certs(cert)?;
    Ok(fingerprint(certs[0].as_ref()))
}

pub fn generate_dev_cert(dir: &Path) -> Result<(PathBuf, PathBuf, String)> {
    std::fs::create_dir_all(dir)?;
    let pair = rcgen::generate_simple_self_signed(vec![
        "localhost".into(),
        "yany-relay".into(),
    ])?;
    let cert_path = dir.join("dev-cert.pem");
    let key_path = dir.join("dev-key.pem");
    std::fs::write(&cert_path, pair.cert.pem())?;
    std::fs::write(&key_path, pair.key_pair.serialize_pem())?;
    let fp = fingerprint(pair.cert.der());
    Ok((cert_path, key_path, fp))
}

#[cfg(test)]
mod tests {
    use super::fingerprint;

    #[test]
    fn fingerprint_is_64_hex() {
        let fp = fingerprint(b"abc");
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn reuses_existing_dev_cert() {
        let dir = std::env::temp_dir().join(format!("yany-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (_, _, fp1) = super::load_or_create_dev_cert(&dir).unwrap();
        let (_, _, fp2) = super::load_or_create_dev_cert(&dir).unwrap();
        assert_eq!(fp1, fp2);
        let _ = std::fs::remove_dir_all(dir);
    }
}

pub fn fingerprint(der: &[u8]) -> String {
    format!("{}", blake3::hash(der))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path).with_context(|| path.display().to_string())?);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<_, _>>()
        .context("read certs")?;
    if certs.is_empty() {
        bail!("no certificates in {}", path.display());
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path).with_context(|| path.display().to_string())?);
    rustls_pemfile::private_key(&mut reader)
        .context("read key")?
        .ok_or_else(|| anyhow::anyhow!("no private key in {}", path.display()))
}
