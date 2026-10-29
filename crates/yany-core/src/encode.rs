use crate::capture::Frame;
use crate::error::YanyError;
use crate::tile::{copy_rect_bgra, split_into_tiles, blit_rect_bgra, Rect, Tile, TileFrame};
use crate::DEFAULT_TILE;

pub trait FrameEncoder: Send {
    fn encode(&mut self, frame: &Frame) -> Result<TileFrame, YanyError>;
}

pub trait FrameDecoder: Send {
    fn decode(&mut self, msg: &TileFrame) -> Result<Frame, YanyError>;
}

/// Lossless zstd tiles. Sharp for UI/text (NoMachine-like). Swap this type, not the session.
pub struct ZstdTileCodec {
    tile: u32,
    level: i32,
    canvas: Option<Frame>,
}

impl ZstdTileCodec {
    pub fn new(tile: u32, level: i32) -> Result<Self, YanyError> {
        if !(1..=512).contains(&tile) {
            return Err(YanyError::Invalid("tile size".into()));
        }
        if !(-7..=3).contains(&level) && !(1..=19).contains(&level) {
            return Err(YanyError::Invalid("zstd level".into()));
        }
        Ok(Self {
            tile,
            level,
            canvas: None,
        })
    }

    pub fn default_realtime() -> Self {
        Self::new(DEFAULT_TILE, -1).expect("static defaults")
    }
}

impl FrameEncoder for ZstdTileCodec {
    fn encode(&mut self, frame: &Frame) -> Result<TileFrame, YanyError> {
        frame.validate()?;
        let screen = Rect {
            x: 0,
            y: 0,
            w: frame.width,
            h: frame.height,
        };
        let dirty = if frame.dirty.is_empty() {
            vec![screen]
        } else {
            frame.dirty.clone()
        };
        let rects = split_into_tiles(&dirty, self.tile, screen)?;
        let mut tiles = Vec::with_capacity(rects.len());
        for rect in rects {
            let raw = copy_rect_bgra(&frame.bgra, frame.width, frame.height, rect)?;
            let zstd_bgra = zstd::encode_all(raw.as_slice(), self.level)
                .map_err(|e| YanyError::Encode(e.to_string()))?;
            if zstd_bgra.len() > 2 * 1024 * 1024 {
                return Err(YanyError::TooLarge(zstd_bgra.len()));
            }
            tiles.push(Tile { rect, zstd_bgra });
        }
        Ok(TileFrame {
            width: frame.width,
            height: frame.height,
            tiles,
        })
    }
}

impl FrameDecoder for ZstdTileCodec {
    fn decode(&mut self, msg: &TileFrame) -> Result<Frame, YanyError> {
        if msg.width == 0 || msg.height == 0 || msg.width > 7680 || msg.height > 4320 {
            return Err(YanyError::Invalid("bad decode geometry".into()));
        }
        let bytes = (msg.width as usize)
            .checked_mul(msg.height as usize)
            .and_then(|px| px.checked_mul(4))
            .ok_or_else(|| YanyError::Invalid("decode overflow".into()))?;
        if self.canvas.as_ref().map(|c| (c.width, c.height)) != Some((msg.width, msg.height)) {
            self.canvas = Some(Frame {
                width: msg.width,
                height: msg.height,
                bgra: vec![0; bytes],
                dirty: vec![],
            });
        }
        let canvas = self.canvas.as_mut().unwrap();
        let mut dirty = Vec::new();
        for tile in &msg.tiles {
            if tile.zstd_bgra.len() > 2 * 1024 * 1024 {
                return Err(YanyError::TooLarge(tile.zstd_bgra.len()));
            }
            let raw = zstd::decode_all(tile.zstd_bgra.as_slice())
                .map_err(|e| YanyError::Encode(e.to_string()))?;
            blit_rect_bgra(&mut canvas.bgra, canvas.width, canvas.height, tile.rect, &raw)?;
            dirty.push(tile.rect);
        }
        canvas.dirty = dirty;
        Ok(canvas.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_preserves_pixels() {
        let mut bgra = vec![0u8; 64 * 64 * 4];
        bgra[100] = 42;
        let frame = Frame {
            width: 64,
            height: 64,
            bgra,
            dirty: vec![Rect {
                x: 0,
                y: 0,
                w: 8,
                h: 8,
            }],
        };
        let mut enc = ZstdTileCodec::default_realtime();
        let mut dec = ZstdTileCodec::default_realtime();
        let msg = enc.encode(&frame).unwrap();
        let out = dec.decode(&msg).unwrap();
        assert_eq!(out.bgra[100], 42);
    }
}
