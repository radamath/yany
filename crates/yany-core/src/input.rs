use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum InputEvent {
    MouseMove { x: u16, y: u16 },
    MouseButton { button: u8, down: bool },
    MouseWheel { delta: i16 },
    Key { vk: u16, down: bool, scan: u16 },
}

/// Absolute mouse coords are 0..=65535 over the captured surface.
pub fn clamp_axis(v: i32) -> u16 {
    v.clamp(0, 65535) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_rejects_out_of_range() {
        assert_eq!(clamp_axis(-10), 0);
        assert_eq!(clamp_axis(70_000), 65535);
        assert_eq!(clamp_axis(100), 100);
    }
}
