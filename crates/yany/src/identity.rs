use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use yany_core::id::HostId;

pub fn data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
        PathBuf::from(dir).join("Yany")
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".yany")
    } else {
        PathBuf::from("yany-data")
    }
}

pub fn load_or_create_id(path: &Path) -> Result<HostId> {
    if path.exists() {
        let raw = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
        return Ok(raw.trim().parse()?);
    }
    let id = HostId::generate();
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    std::fs::write(path, format!("{}\n", id.raw()))?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_generated_id() {
        let dir = std::env::temp_dir().join(format!("yany-id-{}", std::process::id()));
        let path = dir.join("host.id");
        let a = load_or_create_id(&path).unwrap();
        let b = load_or_create_id(&path).unwrap();
        assert_eq!(a, b);
        let _ = std::fs::remove_dir_all(dir);
    }
}
