//! Rotating relay enrollment secret. 128-bit CSPRNG, 15-minute lifetime.

use crate::auth::random_bytes;
use crate::error::YanyError;
use std::fmt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

pub const JOIN_TOKEN_BYTES: usize = 16;
pub const JOIN_TOKEN_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Clone)]
pub struct JoinSecret {
    bytes: [u8; JOIN_TOKEN_BYTES],
    display: String,
    valid_until_unix: u64,
}

impl Drop for JoinSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.display.zeroize();
    }
}

impl fmt::Debug for JoinSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinSecret")
            .field("valid_until_unix", &self.valid_until_unix)
            .finish_non_exhaustive()
    }
}

impl JoinSecret {
    pub fn generate(ttl: Duration) -> Self {
        let bytes = random_bytes::<JOIN_TOKEN_BYTES>();
        Self::from_parts(bytes, unix_now().saturating_add(ttl.as_secs()))
    }

    fn from_parts(bytes: [u8; JOIN_TOKEN_BYTES], valid_until_unix: u64) -> Self {
        Self {
            display: format_token(&bytes),
            bytes,
            valid_until_unix,
        }
    }

    pub fn display(&self) -> &str {
        &self.display
    }

    pub fn valid_until_unix(&self) -> u64 {
        self.valid_until_unix
    }

    pub fn is_expired(&self) -> bool {
        unix_now() >= self.valid_until_unix
    }

    pub fn remaining(&self) -> Duration {
        Duration::from_secs(self.valid_until_unix.saturating_sub(unix_now()))
    }

    pub fn matches_presented(&self, presented: &str) -> bool {
        match parse_token(presented) {
            Ok(got) => ct_eq(&self.bytes, &got),
            Err(_) => false,
        }
    }

    pub fn accepts_join(&self, presented: &str) -> bool {
        !self.is_expired() && self.matches_presented(presented)
    }

    pub fn write_file(&self, path: &Path) -> Result<(), YanyError> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let body = format!("{}\n{}\n", self.display, self.valid_until_unix);
        let tmp = path.with_extension("token.tmp");
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

    pub fn read_file(path: &Path) -> Result<Self, YanyError> {
        let raw = std::fs::read_to_string(path)?;
        parse_file(&raw)
    }

    pub fn load_or_create(path: &Path, ttl: Duration) -> Result<Self, YanyError> {
        if path.is_file() {
            if let Ok(existing) = Self::read_file(path) {
                if !existing.is_expired() {
                    return Ok(existing);
                }
            }
        }
        let next = Self::generate(ttl);
        next.write_file(path)?;
        Ok(next)
    }

    pub fn cli_report(&self) -> String {
        let left = self.remaining();
        let mins = left.as_secs() / 60;
        let secs = left.as_secs() % 60;
        format!(
            "Yany kayıt şifresi\n  {}\n\nKalan süre: {mins} dk {secs} sn\nYeni istemciye yalnızca bu değeri yazın.\n",
            self.display
        )
    }
}

pub fn parse_token(s: &str) -> Result<[u8; JOIN_TOKEN_BYTES], YanyError> {
    let hex: String = s
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex.len() != JOIN_TOKEN_BYTES * 2 {
        return Err(YanyError::Invalid("join token must be 128-bit hex".into()));
    }
    let mut out = [0u8; JOIN_TOKEN_BYTES];
    for i in 0..JOIN_TOKEN_BYTES {
        let hi = nibble(hex.as_bytes()[i * 2])?;
        let lo = nibble(hex.as_bytes()[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

pub fn format_token(bytes: &[u8; JOIN_TOKEN_BYTES]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or("0000"))
        .collect::<Vec<_>>()
        .join("-")
}

pub fn sanitize_display_name(name: &str) -> Result<String, YanyError> {
    let trimmed = name.trim();
    let count = trimmed.chars().count();
    if count == 0 || count > 32 {
        return Err(YanyError::Invalid("display name must be 1..=32 characters".into()));
    }
    if trimmed.chars().any(|c| c.is_control() || c == '/' || c == '\\') {
        return Err(YanyError::Invalid("display name has invalid characters".into()));
    }
    Ok(trimmed.to_string())
}

fn parse_file(raw: &str) -> Result<JoinSecret, YanyError> {
    let mut lines = raw.lines();
    let token = lines
        .next()
        .ok_or_else(|| YanyError::Invalid("empty join token file".into()))?;
    let until = lines
        .next()
        .ok_or_else(|| YanyError::Invalid("join token file missing expiry".into()))?;
    let bytes = parse_token(token)?;
    let valid_until_unix: u64 = until
        .trim()
        .parse()
        .map_err(|_| YanyError::Invalid("join token expiry".into()))?;
    Ok(JoinSecret::from_parts(bytes, valid_until_unix))
}

fn nibble(c: u8) -> Result<u8, YanyError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(YanyError::Invalid("join token hex".into())),
    }
}

fn ct_eq(a: &[u8; JOIN_TOKEN_BYTES], b: &[u8; JOIN_TOKEN_BYTES]) -> bool {
    let mut diff = 0u8;
    for i in 0..JOIN_TOKEN_BYTES {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_is_8_groups_of_4_hex() {
        let bytes = [0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x32];
        let shown = format_token(&bytes);
        assert_eq!(shown, "abcd-ef01-2345-6789-aabb-ccdd-eeff-1032");
        assert_eq!(parse_token(&shown).unwrap(), bytes);
        assert_eq!(parse_token("ABCD EF01 2345 6789 AABB CCDD EEFF 1032").unwrap(), bytes);
    }

    #[test]
    fn rejects_short_and_non_hex() {
        assert!(parse_token("abcd").is_err());
        assert!(parse_token("zzzz-zzzz-zzzz-zzzz-zzzz-zzzz-zzzz-zzzz").is_err());
    }

    #[test]
    fn matches_ignores_dashes_and_case() {
        let secret = JoinSecret::from_parts([7u8; 16], unix_now() + 60);
        let shown = secret.display().to_string();
        assert!(secret.matches_presented(&shown));
        assert!(secret.matches_presented(&shown.replace('-', "").to_uppercase()));
        assert!(!secret.matches_presented("0000-0000-0000-0000-0000-0000-0000-0000"));
        assert!(secret.accepts_join(&shown));
        let expired = JoinSecret::from_parts([7u8; 16], unix_now() - 1);
        assert!(!expired.accepts_join(&shown));
    }

    #[test]
    fn debug_does_not_leak_token() {
        let secret = JoinSecret::from_parts([0x11u8; 16], 99);
        let dumped = format!("{secret:?}");
        assert!(!dumped.contains("1111"));
        assert!(!dumped.contains(secret.display()));
    }

    #[test]
    fn file_roundtrip_and_reuse_unexpired() {
        let dir = std::env::temp_dir().join(format!("yany-join-{}", std::process::id()));
        let path = dir.join("join.token");
        let _ = std::fs::remove_dir_all(&dir);
        let first = JoinSecret::load_or_create(&path, JOIN_TOKEN_TTL).unwrap();
        let shown = first.display().to_string();
        let until = first.valid_until_unix();
        drop(first);
        let second = JoinSecret::load_or_create(&path, JOIN_TOKEN_TTL).unwrap();
        assert_eq!(second.display(), shown);
        assert_eq!(second.valid_until_unix(), until);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn load_or_create_replaces_expired() {
        let dir = std::env::temp_dir().join(format!("yany-join-exp-{}", std::process::id()));
        let path = dir.join("join.token");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let old = JoinSecret::from_parts([9u8; 16], unix_now() - 5);
        old.write_file(&path).unwrap();
        let next = JoinSecret::load_or_create(&path, JOIN_TOKEN_TTL).unwrap();
        assert_ne!(parse_token(next.display()).unwrap(), [9u8; 16]);
        assert!(!next.is_expired());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sanitize_name_bounds() {
        assert!(sanitize_display_name("  pc-1  ").is_ok());
        assert!(sanitize_display_name("").is_err());
        assert!(sanitize_display_name(&"x".repeat(33)).is_err());
        assert!(sanitize_display_name("bad\nname").is_err());
    }
}
