use crate::error::YanyError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

impl Rect {
    pub fn intersect(self, other: Rect) -> Option<Rect> {
        let x = self.x.max(other.x);
        let y = self.y.max(other.y);
        let r = (self.x + self.w).min(other.x + other.w);
        let b = (self.y + self.h).min(other.y + other.h);
        if r > x && b > y {
            Some(Rect {
                x,
                y,
                w: r - x,
                h: b - y,
            })
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tile {
    pub rect: Rect,
    pub zstd_bgra: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TileFrame {
    pub width: u32,
    pub height: u32,
    pub tiles: Vec<Tile>,
}

pub fn split_into_tiles(dirty: &[Rect], tile: u32, screen: Rect) -> Result<Vec<Rect>, YanyError> {
    if tile == 0 || tile > 512 {
        return Err(YanyError::Invalid("tile size must be 1..=512".into()));
    }
    let mut out = Vec::new();
    for rect in dirty {
        let Some(clipped) = rect.intersect(screen) else {
            continue;
        };
        let x0 = (clipped.x / tile) * tile;
        let y0 = (clipped.y / tile) * tile;
        let x1 = clipped.x + clipped.w;
        let y1 = clipped.y + clipped.h;
        let mut y = y0;
        while y < y1 {
            let mut x = x0;
            while x < x1 {
                let cell = Rect {
                    x,
                    y,
                    w: tile,
                    h: tile,
                };
                if let Some(hit) = cell.intersect(screen) {
                    out.push(hit);
                }
                x += tile;
            }
            y += tile;
        }
    }
    out.sort_by_key(|r| (r.y, r.x, r.w, r.h));
    out.dedup();
    if out.len() > 4096 {
        return Err(YanyError::Invalid("too many dirty tiles".into()));
    }
    Ok(out)
}

pub fn copy_rect_bgra(
    src: &[u8],
    width: u32,
    height: u32,
    rect: Rect,
) -> Result<Vec<u8>, YanyError> {
    if rect.w == 0 || rect.h == 0 {
        return Err(YanyError::Invalid("empty rect".into()));
    }
    if rect.x.checked_add(rect.w).is_none() || rect.y.checked_add(rect.h).is_none() {
        return Err(YanyError::Invalid("rect overflow".into()));
    }
    if rect.x + rect.w > width || rect.y + rect.h > height {
        return Err(YanyError::Invalid("rect outside frame".into()));
    }
    let mut buf = vec![0u8; (rect.w as usize) * (rect.h as usize) * 4];
    for row in 0..rect.h as usize {
        let src_off = ((rect.y as usize + row) * width as usize + rect.x as usize) * 4;
        let dst_off = row * (rect.w as usize) * 4;
        let len = (rect.w as usize) * 4;
        buf[dst_off..dst_off + len].copy_from_slice(&src[src_off..src_off + len]);
    }
    Ok(buf)
}

pub fn blit_rect_bgra(
    dst: &mut [u8],
    width: u32,
    height: u32,
    rect: Rect,
    tile: &[u8],
) -> Result<(), YanyError> {
    let expect = (rect.w as usize)
        .checked_mul(rect.h as usize)
        .and_then(|n| n.checked_mul(4))
        .ok_or_else(|| YanyError::Invalid("blit overflow".into()))?;
    if tile.len() != expect {
        return Err(YanyError::Invalid("tile buffer mismatch".into()));
    }
    if rect.x + rect.w > width || rect.y + rect.h > height {
        return Err(YanyError::Invalid("blit outside frame".into()));
    }
    for row in 0..rect.h as usize {
        let dst_off = ((rect.y as usize + row) * width as usize + rect.x as usize) * 4;
        let src_off = row * (rect.w as usize) * 4;
        let len = (rect.w as usize) * 4;
        dst[dst_off..dst_off + len].copy_from_slice(&tile[src_off..src_off + len]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_aligns_and_clips() {
        let screen = Rect {
            x: 0,
            y: 0,
            w: 100,
            h: 100,
        };
        let dirty = [Rect {
            x: 60,
            y: 60,
            w: 50,
            h: 50,
        }];
        let tiles = split_into_tiles(&dirty, 64, screen).unwrap();
        assert!(!tiles.is_empty());
        assert!(tiles.iter().all(|t| t.x + t.w <= 100 && t.y + t.h <= 100));
    }

    #[test]
    fn copy_and_blit_roundtrip() {
        let mut src = vec![0u8; 4 * 4 * 4];
        src[4 * 4 + 4] = 9;
        let rect = Rect {
            x: 1,
            y: 1,
            w: 1,
            h: 1,
        };
        let tile = copy_rect_bgra(&src, 4, 4, rect).unwrap();
        let mut dst = vec![0u8; src.len()];
        blit_rect_bgra(&mut dst, 4, 4, rect, &tile).unwrap();
        assert_eq!(dst[4 * 4 + 4], 9);
    }

    #[test]
    fn rejects_out_of_bounds_copy() {
        let src = vec![0u8; 16];
        let rect = Rect {
            x: 3,
            y: 0,
            w: 2,
            h: 1,
        };
        assert!(copy_rect_bgra(&src, 4, 1, rect).is_err());
    }
}
