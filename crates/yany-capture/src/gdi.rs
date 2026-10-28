use yany_core::capture::{CaptureBackend, Frame};
use yany_core::config::CaptureKind;
use yany_core::tile::{copy_rect_bgra, split_into_tiles, Rect};
use yany_core::{YanyError, DEFAULT_TILE};

use windows::Win32::Graphics::Gdi::{
    BitBlt, CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject,
    GetDC, ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HGDIOBJ,
    SRCCOPY,
};
use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

pub struct GdiCapture {
    width: u32,
    height: u32,
    prev: Option<Vec<u8>>,
}

impl GdiCapture {
    pub fn new() -> Result<Self, YanyError> {
        unsafe {
            let width = GetSystemMetrics(SM_CXSCREEN);
            let height = GetSystemMetrics(SM_CYSCREEN);
            if width <= 0 || height <= 0 {
                return Err(YanyError::Capture("GDI screen size invalid".into()));
            }
            Ok(Self {
                width: width as u32,
                height: height as u32,
                prev: None,
            })
        }
    }
}

impl CaptureBackend for GdiCapture {
    fn kind(&self) -> CaptureKind {
        CaptureKind::Gdi
    }

    fn start(&mut self) -> Result<(), YanyError> {
        self.prev = None;
        Ok(())
    }

    fn next_frame(&mut self) -> Result<Option<Frame>, YanyError> {
        let bgra = unsafe { grab_bgra(self.width, self.height)? };
        let dirty = if let Some(prev) = &self.prev {
            tile_diff(prev, &bgra, self.width, self.height)?
        } else {
            vec![Rect {
                x: 0,
                y: 0,
                w: self.width,
                h: self.height,
            }]
        };
        self.prev = Some(bgra.clone());
        if dirty.is_empty() {
            return Ok(None);
        }
        let frame = Frame {
            width: self.width,
            height: self.height,
            bgra,
            dirty,
        };
        frame.validate()?;
        Ok(Some(frame))
    }
}

fn tile_diff(prev: &[u8], now: &[u8], w: u32, h: u32) -> Result<Vec<Rect>, YanyError> {
    let screen = Rect {
        x: 0,
        y: 0,
        w,
        h,
    };
    let cells = split_into_tiles(&[screen], DEFAULT_TILE, screen)?;
    let mut dirty = Vec::new();
    for cell in cells {
        let a = copy_rect_bgra(prev, w, h, cell)?;
        let b = copy_rect_bgra(now, w, h, cell)?;
        if a != b {
            dirty.push(cell);
        }
    }
    Ok(dirty)
}

unsafe fn grab_bgra(width: u32, height: u32) -> Result<Vec<u8>, YanyError> {
    let hdc = GetDC(None);
    if hdc.is_invalid() {
        return Err(YanyError::Capture("GetDC failed".into()));
    }
    let mem = CreateCompatibleDC(hdc);
    if mem.is_invalid() {
        ReleaseDC(None, hdc);
        return Err(YanyError::Capture("CreateCompatibleDC failed".into()));
    }
    let info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width as i32,
            biHeight: -(height as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut bits = std::ptr::null_mut();
    let dib = CreateDIBSection(mem, &info, DIB_RGB_COLORS, &mut bits, None, 0);
    if dib.is_err() || bits.is_null() {
        let _ = DeleteDC(mem);
        ReleaseDC(None, hdc);
        return Err(YanyError::Capture("CreateDIBSection failed".into()));
    }
    let dib = dib.unwrap();
    let old = SelectObject(mem, HGDIOBJ(dib.0));
    let ok = BitBlt(mem, 0, 0, width as i32, height as i32, hdc, 0, 0, SRCCOPY);
    let size = width as usize * height as usize * 4;
    let mut bgra = vec![0u8; size];
    if ok.is_ok() {
        std::ptr::copy_nonoverlapping(bits as *const u8, bgra.as_mut_ptr(), size);
    }
    SelectObject(mem, old);
    let _ = DeleteObject(HGDIOBJ(dib.0));
    let _ = DeleteDC(mem);
    ReleaseDC(None, hdc);
    if ok.is_err() {
        return Err(YanyError::Capture("BitBlt failed".into()));
    }
    Ok(bgra)
}
