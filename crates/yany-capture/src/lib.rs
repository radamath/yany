use yany_core::capture::{CaptureBackend, MockCapture};
use yany_core::config::CaptureKind;
use yany_core::YanyError;

#[cfg(windows)]
mod dxgi;
#[cfg(windows)]
mod gdi;

/// Factory: DXGI by default, GDI if DXGI is unwanted, Mock for tests.
pub fn open_capture(kind: CaptureKind) -> Result<Box<dyn CaptureBackend>, YanyError> {
    match kind {
        CaptureKind::Mock => Ok(Box::new(MockCapture::new(Vec::new()))),
        CaptureKind::Dxgi => {
            #[cfg(windows)]
            {
                Ok(Box::new(dxgi::DxgiCapture::new()?))
            }
            #[cfg(not(windows))]
            {
                Err(YanyError::Capture("DXGI is Windows-only".into()))
            }
        }
        CaptureKind::Gdi => {
            #[cfg(windows)]
            {
                Ok(Box::new(gdi::GdiCapture::new()?))
            }
            #[cfg(not(windows))]
            {
                Err(YanyError::Capture("GDI is Windows-only".into()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_factory() {
        let mut cap = open_capture(CaptureKind::Mock).unwrap();
        assert_eq!(cap.kind(), CaptureKind::Mock);
        cap.start().unwrap();
        assert!(cap.next_frame().unwrap().is_none());
    }
}
