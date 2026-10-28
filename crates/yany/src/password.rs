use anyhow::{bail, Context, Result};
use std::path::Path;
use zeroize::Zeroizing;
use yany_core::auth::{random_bytes, validate_password};

pub fn load(path: &Path) -> Result<Zeroizing<String>> {
    let raw = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
    let pw = raw.trim().to_string();
    validate_password(&pw)?;
    Ok(Zeroizing::new(pw))
}

pub fn write_random(path: &Path) -> Result<Zeroizing<String>> {
    let bytes = random_bytes::<12>();
    let pw = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    std::fs::write(path, format!("{pw}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    validate_password(&pw)?;
    Ok(Zeroizing::new(pw))
}

pub fn require_file(path: &Path) -> Result<Zeroizing<String>> {
    if !path.exists() {
        bail!(
            "password file {} missing — create it (8+ chars, one line) or pass --write-password",
            path.display()
        );
    }
    load(path)
}
