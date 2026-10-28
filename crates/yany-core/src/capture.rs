use crate::config::CaptureKind;
use crate::error::YanyError;
use crate::tile::Rect;

/// BGRA8 desktop frame. Owned so backends cannot alias GPU memory.
#[derive(Clone, Debug)]
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub bgra: Vec<u8>,
    pub dirty: Vec<Rect>,
}

impl Frame {
    pub fn validate(&self) -> Result<(), YanyError> {
        let expected = (self.width as usize)
            .checked_mul(self.height as usize)
            .and_then(|px| px.checked_mul(4))
            .ok_or_else(|| YanyError::Invalid("frame size overflow".into()))?;
        if self.bgra.len() != expected {
            return Err(YanyError::Invalid("frame buffer size mismatch".into()));
        }
        if self.width == 0 || self.height == 0 || self.width > 7680 || self.height > 4320 {
            return Err(YanyError::Invalid("unsupported frame geometry".into()));
        }
        Ok(())
    }
}

pub trait CaptureBackend: Send {
    fn kind(&self) -> CaptureKind;
    fn start(&mut self) -> Result<(), YanyError>;
    fn next_frame(&mut self) -> Result<Option<Frame>, YanyError>;
}

/// In-memory backend for tests and for swapping DXGI without touching the session loop.
pub struct MockCapture {
    frames: Vec<Frame>,
    index: usize,
}

impl MockCapture {
    pub fn new(frames: Vec<Frame>) -> Self {
        Self { frames, index: 0 }
    }
}

impl CaptureBackend for MockCapture {
    fn kind(&self) -> CaptureKind {
        CaptureKind::Mock
    }

    fn start(&mut self) -> Result<(), YanyError> {
        self.index = 0;
        Ok(())
    }

    fn next_frame(&mut self) -> Result<Option<Frame>, YanyError> {
        if self.index >= self.frames.len() {
            return Ok(None);
        }
        let frame = self.frames[self.index].clone();
        frame.validate()?;
        self.index += 1;
        Ok(Some(frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_mismatched_buffer() {
        let f = Frame {
            width: 2,
            height: 2,
            bgra: vec![0; 4],
            dirty: vec![],
        };
        assert!(f.validate().is_err());
    }

    #[test]
    fn mock_yields_then_none() {
        let frame = Frame {
            width: 1,
            height: 1,
            bgra: vec![1, 2, 3, 255],
            dirty: vec![],
        };
        let mut cap = MockCapture::new(vec![frame]);
        cap.start().unwrap();
        assert!(cap.next_frame().unwrap().is_some());
        assert!(cap.next_frame().unwrap().is_none());
    }
}
