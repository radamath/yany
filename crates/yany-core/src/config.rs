use serde::{Deserialize, Serialize};

/// Capture backend. DXGI is default; GDI is the swap path if DXGI misbehaves.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureKind {
    Dxgi,
    Gdi,
    Mock,
}

impl CaptureKind {
    pub fn parse(raw: &str) -> Result<Self, crate::YanyError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "dxgi" => Ok(Self::Dxgi),
            "gdi" => Ok(Self::Gdi),
            "mock" => Ok(Self::Mock),
            other => Err(crate::YanyError::Invalid(format!(
                "unknown capture backend '{other}' (dxgi|gdi|mock)"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dxgi => "dxgi",
            Self::Gdi => "gdi",
            Self::Mock => "mock",
        }
    }
}

impl Default for CaptureKind {
    fn default() -> Self {
        Self::Dxgi
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_backends() {
        assert_eq!(CaptureKind::parse("DXGI").unwrap(), CaptureKind::Dxgi);
        assert_eq!(CaptureKind::parse("gdi").unwrap(), CaptureKind::Gdi);
        assert!(CaptureKind::parse("deskrt").is_err());
    }
}
