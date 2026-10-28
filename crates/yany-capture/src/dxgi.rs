use yany_core::capture::{CaptureBackend, Frame};
use yany_core::config::CaptureKind;
use yany_core::tile::Rect;
use yany_core::YanyError;

use windows::core::Interface;
use windows::Win32::Foundation::RECT;
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_UNKNOWN;
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_CPU_ACCESS_READ,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ,
    D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC,
};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput1, IDXGIOutputDuplication,
    IDXGIResource,     DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
};

pub struct DxgiCapture {
    #[allow(dead_code)]
    device: ID3D11Device,
    ctx: ID3D11DeviceContext,
    dup: IDXGIOutputDuplication,
    staging: ID3D11Texture2D,
    width: u32,
    height: u32,
    first: bool,
}

struct AcquiredFrame {
    dup: IDXGIOutputDuplication,
}

impl Drop for AcquiredFrame {
    fn drop(&mut self) {
        unsafe {
            let _ = self.dup.ReleaseFrame();
        }
    }
}

impl DxgiCapture {
    pub fn new() -> Result<Self, YanyError> {
        unsafe { Self::create() }
    }

    unsafe fn create() -> Result<Self, YanyError> {
        let factory: IDXGIFactory1 = CreateDXGIFactory1()
            .map_err(|e| YanyError::Capture(format!("DXGI factory: {e}")))?;
        let adapter: IDXGIAdapter1 = factory
            .EnumAdapters1(0)
            .map_err(|e| YanyError::Capture(format!("adapter: {e}")))?;
        let output = adapter
            .EnumOutputs(0)
            .map_err(|e| YanyError::Capture(format!("output: {e}")))?;
        let mut device = None;
        let mut ctx = None;
        D3D11CreateDevice(
            &adapter,
            D3D_DRIVER_TYPE_UNKNOWN,
            None,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut ctx),
        )
        .map_err(|e| YanyError::Capture(format!("D3D11 device: {e}")))?;
        let device = device.ok_or_else(|| YanyError::Capture("no D3D device".into()))?;
        let ctx = ctx.ok_or_else(|| YanyError::Capture("no D3D context".into()))?;
        let output1: IDXGIOutput1 = output
            .cast()
            .map_err(|e| YanyError::Capture(format!("IDXGIOutput1: {e}")))?;
        let dup = output1
            .DuplicateOutput(&device)
            .map_err(|e| YanyError::Capture(format!("DuplicateOutput: {e}")))?;
        let desc = dup.GetDesc();
        let width = desc.ModeDesc.Width;
        let height = desc.ModeDesc.Height;
        if width == 0 || height == 0 {
            return Err(YanyError::Capture("desktop size is zero".into()));
        }
        let tex_desc = D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
        };
        let mut staging = None;
        device
            .CreateTexture2D(&tex_desc, None, Some(&mut staging))
            .map_err(|e| YanyError::Capture(format!("staging texture: {e}")))?;
        let staging = staging.ok_or_else(|| YanyError::Capture("no staging texture".into()))?;
        Ok(Self {
            device,
            ctx,
            dup,
            staging,
            width,
            height,
            first: true,
        })
    }

    unsafe fn recreate(&mut self) -> Result<(), YanyError> {
        *self = Self::create()?;
        Ok(())
    }
}

impl CaptureBackend for DxgiCapture {
    fn kind(&self) -> CaptureKind {
        CaptureKind::Dxgi
    }

    fn start(&mut self) -> Result<(), YanyError> {
        Ok(())
    }

    fn next_frame(&mut self) -> Result<Option<Frame>, YanyError> {
        unsafe {
            let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
            let mut resource: Option<IDXGIResource> = None;
            match self.dup.AcquireNextFrame(16, &mut info, &mut resource) {
                Ok(()) => {}
                Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(None),
                Err(e) if e.code() == DXGI_ERROR_ACCESS_LOST => {
                    self.recreate()?;
                    return Ok(None);
                }
                Err(e) => return Err(YanyError::Capture(format!("AcquireNextFrame: {e}"))),
            }
            let _guard = AcquiredFrame {
                dup: self.dup.clone(),
            };
            let Some(resource) = resource else {
                return Ok(None);
            };
            let tex: ID3D11Texture2D = resource
                .cast()
                .map_err(|e| YanyError::Capture(format!("frame texture: {e}")))?;
            self.ctx.CopyResource(&self.staging, &tex);
            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            self.ctx
                .Map(&self.staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
                .map_err(|e| YanyError::Capture(format!("Map: {e}")))?;
            let pitch = mapped.RowPitch as usize;
            let mut bgra = vec![0u8; self.width as usize * self.height as usize * 4];
            let src = std::slice::from_raw_parts(mapped.pData as *const u8, pitch * self.height as usize);
            for y in 0..self.height as usize {
                let s = y * pitch;
                let d = y * self.width as usize * 4;
                bgra[d..d + self.width as usize * 4]
                    .copy_from_slice(&src[s..s + self.width as usize * 4]);
            }
            self.ctx.Unmap(&self.staging, 0);

            let mut dirty = dirty_rects(&self.dup, self.width, self.height)?;
            drop(tex);
            drop(resource);

            if self.first {
                dirty = vec![Rect {
                    x: 0,
                    y: 0,
                    w: self.width,
                    h: self.height,
                }];
                self.first = false;
            } else if dirty.is_empty() {
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
}

unsafe fn dirty_rects(
    dup: &IDXGIOutputDuplication,
    width: u32,
    height: u32,
) -> Result<Vec<Rect>, YanyError> {
    let mut needed = 0u32;
    let probe = dup.GetFrameDirtyRects(0, std::ptr::null_mut(), &mut needed);
    if probe.is_err() && needed == 0 {
        return Ok(vec![Rect {
            x: 0,
            y: 0,
            w: width,
            h: height,
        }]);
    }
    let count = (needed as usize) / std::mem::size_of::<RECT>();
    if count == 0 {
        return Ok(Vec::new());
    }
    if count > 4096 {
        return Err(YanyError::Capture("too many dirty rects".into()));
    }
    let mut buf = vec![RECT::default(); count];
    dup.GetFrameDirtyRects(needed, buf.as_mut_ptr(), &mut needed)
        .map_err(|e| YanyError::Capture(format!("GetFrameDirtyRects: {e}")))?;
    let screen = Rect {
        x: 0,
        y: 0,
        w: width,
        h: height,
    };
    let mut out = Vec::new();
    for r in buf {
        let rect = Rect {
            x: r.left.max(0) as u32,
            y: r.top.max(0) as u32,
            w: (r.right - r.left).max(0) as u32,
            h: (r.bottom - r.top).max(0) as u32,
        };
        if let Some(hit) = rect.intersect(screen) {
            out.push(hit);
        }
    }
    Ok(out)
}
