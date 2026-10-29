use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ClientConfig {
    pub relay: String,
    #[serde(default)]
    pub fingerprint: String,
    pub join_token: String,
    #[serde(default)]
    pub display_name: String,
}

pub fn config_path() -> PathBuf {
    crate::identity::data_dir().join("client.toml")
}

pub fn load(path: &Path) -> Result<Option<ClientConfig>> {
    if !path.is_file() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
    let cfg: ClientConfig = toml::from_str(&raw)?;
    Ok(Some(cfg))
}

pub fn save(path: &Path, cfg: &ClientConfig) -> Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    let body = toml::to_string_pretty(cfg)?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&tmp)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&tmp, perms)?;
    }
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn default_display_name() -> String {
    let raw = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "yany-pc".into());
    let truncated: String = raw.chars().take(32).collect();
    yany_core::join_token::sanitize_display_name(&truncated).unwrap_or_else(|_| "yany-pc".into())
}

pub fn normalize_relay(input: &str) -> Result<String> {
    let s = input.trim();
    if s.is_empty() || s.len() > 253 {
        bail!("relay address too long or empty");
    }
    if s.contains("://") || s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        bail!("invalid relay address");
    }
    let (host, port) = split_host_port(s)?;
    if host.is_empty() || host.len() > 253 {
        bail!("invalid relay host");
    }
    let port = port.unwrap_or(443);
    if port == 0 {
        bail!("invalid relay port");
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_unspecified() || ip.is_multicast() {
            bail!("invalid relay ip");
        }
        if matches!(ip, IpAddr::V6(_)) {
            return Ok(format!("[{host}]:{port}"));
        }
        return Ok(format!("{host}:{port}"));
    }
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        bail!("invalid relay host");
    }
    Ok(format!("{host}:{port}"))
}

fn split_host_port(s: &str) -> Result<(String, Option<u16>)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| anyhow::anyhow!("invalid ipv6 relay address"))?;
        if tail.is_empty() {
            return Ok((host.to_string(), None));
        }
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("invalid ipv6 relay address"))?;
        let port: u16 = port.parse().map_err(|_| anyhow::anyhow!("invalid relay port"))?;
        return Ok((host.to_string(), Some(port)));
    }
    if let Some((host, port)) = s.rsplit_once(':') {
        if host.parse::<IpAddr>().is_ok() || !host.is_empty() {
            if port.chars().all(|c| c.is_ascii_digit()) {
                let port: u16 = port.parse().map_err(|_| anyhow::anyhow!("invalid relay port"))?;
                return Ok((host.to_string(), Some(port)));
            }
        }
    }
    Ok((s.to_string(), None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_port_443() {
        assert_eq!(normalize_relay("188.132.215.103").unwrap(), "188.132.215.103:443");
        assert_eq!(
            normalize_relay("188.132.215.103:443").unwrap(),
            "188.132.215.103:443"
        );
    }

    #[test]
    fn rejects_scheme_and_spaces() {
        assert!(normalize_relay("https://x").is_err());
        assert!(normalize_relay("a b").is_err());
        assert!(normalize_relay("0.0.0.0").is_err());
    }

    #[test]
    fn config_roundtrip() {
        let dir = std::env::temp_dir().join(format!("yany-cfg-{}", std::process::id()));
        let path = dir.join("client.toml");
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = ClientConfig {
            relay: "127.0.0.1:443".into(),
            fingerprint: "ab".repeat(32),
            join_token: "abcd-ef01-2345-6789-aabb-ccdd-eeff-1032".into(),
            display_name: "pc".into(),
        };
        save(&path, &cfg).unwrap();
        let got = load(&path).unwrap().unwrap();
        assert_eq!(got.relay, cfg.relay);
        assert_eq!(got.join_token, cfg.join_token);
        let _ = std::fs::remove_dir_all(dir);
    }
}
