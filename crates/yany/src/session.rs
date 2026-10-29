use crate::pipe::{MsgPipe, StreamPipe, UdpPipe, UdpRecv, UdpSend};
use anyhow::{bail, Context, Result};
use minifb::{Key, MouseButton, MouseMode, Window, WindowOptions};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use yany_capture::open_capture;
use yany_core::auth::random_bytes;
use yany_core::capture::{CaptureBackend, Frame};
use yany_core::config::CaptureKind;
use yany_core::crypto::SessionKeys;
use yany_core::encode::{FrameDecoder, FrameEncoder, ZstdTileCodec};
use yany_core::framing::{read_msg, write_msg};
use yany_core::input::{clamp_axis, InputEvent};
use yany_core::latest::LatestSlot;
use yany_core::protocol::ControlMsg;
use yany_core::tile::TileFrame;

pub async fn host_handshake_and_media<R, W>(
    reader: R,
    writer: W,
    password: &str,
    capture: CaptureKind,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut pipe = StreamPipe { reader, writer };
    let keys = handshake_keys(|| host_keys(&mut pipe, password)).await?;
    let cap = open_capture(capture)
        .or_else(|_| open_capture(CaptureKind::Gdi))
        .with_context(|| {
            format!(
                "capture backend '{}' failed — try --capture gdi",
                capture.as_str()
            )
        })?;
    host_media(pipe.reader, pipe.writer, keys, cap).await
}

pub async fn host_handshake_and_media_udp(
    mut pipe: UdpPipe,
    password: &str,
    capture: CaptureKind,
) -> Result<()> {
    let keys = handshake_keys(|| host_keys(&mut pipe, password)).await?;
    let cap = open_capture(capture)
        .or_else(|_| open_capture(CaptureKind::Gdi))
        .with_context(|| {
            format!(
                "capture backend '{}' failed — try --capture gdi",
                capture.as_str()
            )
        })?;
    let (recv, send) = pipe.into_split();
    host_media_udp(recv, send, keys, cap).await
}

async fn handshake_keys<F, Fut>(op: F) -> Result<SessionKeys>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<SessionKeys>>,
{
    tokio::time::timeout(Duration::from_secs(8), op())
        .await
        .map_err(|_| anyhow::anyhow!("handshake timeout"))?
}

async fn host_keys<P: MsgPipe>(pipe: &mut P, password: &str) -> Result<SessionKeys> {
    let nonce = random_bytes::<32>();
    pipe.send_msg(&ControlMsg::Challenge { nonce }).await?;
    let keys = SessionKeys::derive(password, &nonce, true)?;
    match pipe.recv_msg().await? {
        ControlMsg::Auth { proof } => keys.verify_auth_proof(&proof)?,
        ControlMsg::Disconnect { reason } => bail!("viewer left: {reason}"),
        other => bail!("expected auth, got {other:?}"),
    }
    pipe.send_msg(&ControlMsg::AuthOk).await?;
    Ok(keys)
}

pub async fn viewer_handshake_and_media<R, W>(
    reader: R,
    writer: W,
    password: &str,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut pipe = StreamPipe { reader, writer };
    let keys = handshake_keys(|| viewer_keys(&mut pipe, password)).await?;
    viewer_media(pipe.reader, pipe.writer, keys).await
}

pub async fn viewer_handshake_and_media_udp(mut pipe: UdpPipe, password: &str) -> Result<()> {
    let keys = handshake_keys(|| viewer_keys(&mut pipe, password)).await?;
    let (recv, send) = pipe.into_split();
    viewer_media_udp(recv, send, keys).await
}

async fn viewer_keys<P: MsgPipe>(pipe: &mut P, password: &str) -> Result<SessionKeys> {
    let challenge = match pipe.recv_msg().await? {
        ControlMsg::Challenge { nonce } => nonce,
        ControlMsg::Error { message } => bail!("relay: {message}"),
        other => bail!("expected challenge, got {other:?}"),
    };
    let keys = SessionKeys::derive(password, &challenge, false)?;
    let proof = SessionKeys::auth_proof(password, &challenge)?;
    pipe.send_msg(&ControlMsg::Auth { proof }).await?;
    match pipe.recv_msg().await? {
        ControlMsg::AuthOk => {}
        ControlMsg::AuthFail => bail!("authentication failed"),
        ControlMsg::Error { message } => bail!("relay: {message}"),
        other => bail!("expected AuthOk, got {other:?}"),
    }
    Ok(keys)
}

pub async fn host_media<R, W>(
    mut reader: R,
    mut writer: W,
    keys: SessionKeys,
    cap: Box<dyn CaptureBackend>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let slot = Arc::new(LatestSlot::new());
    let ping = Arc::new(tokio::sync::Notify::new());
    let slot_c = slot.clone();
    let ping_c = ping.clone();
    std::thread::Builder::new()
        .name("yany-capture".into())
        .spawn(move || capture_loop(cap, slot_c, ping_c))
        .context("capture thread")?;

    let mut encoder = ZstdTileCodec::default_realtime();
    let mut frame_seq = 1u64;
    let mut last_input_seq = 0u64;
    loop {
        if let Some(frame) = slot.take() {
            let tiles = encoder.encode(&frame)?;
            if tiles.tiles.is_empty() {
                continue;
            }
            let ciphertext = keys.seal_bincode(frame_seq, b"yany-frame", &tiles)?;
            write_msg(&mut writer, &ControlMsg::Frame { seq: frame_seq, ciphertext }).await?;
            frame_seq = frame_seq.wrapping_add(1);
            if frame_seq == 0 {
                frame_seq = 1;
            }
            continue;
        }
        tokio::select! {
            biased;
            msg = read_msg(&mut reader) => {
                match msg? {
                    ControlMsg::Input { seq, ciphertext } => {
                        if seq <= last_input_seq {
                            continue;
                        }
                        last_input_seq = seq;
                        let events: Vec<InputEvent> = keys.open_bincode(seq, b"yany-input", &ciphertext)?;
                        if events.len() > 64 {
                            bail!("input batch too large");
                        }
                        if let Err(e) = yany_input::inject(&events) {
                            tracing::warn!("inject: {e}");
                        }
                    }
                    ControlMsg::Disconnect { reason } => {
                        tracing::info!("viewer disconnected: {reason}");
                        break;
                    }
                    ControlMsg::Error { message } => bail!("session error: {message}"),
                    other => bail!("unexpected host msg {other:?}"),
                }
            }
            _ = ping.notified() => {}
        }
    }
    Ok(())
}

async fn host_media_udp(
    mut recv: UdpRecv,
    mut send: UdpSend,
    keys: SessionKeys,
    cap: Box<dyn CaptureBackend>,
) -> Result<()> {
    let slot = Arc::new(LatestSlot::new());
    let ping = Arc::new(tokio::sync::Notify::new());
    let slot_c = slot.clone();
    let ping_c = ping.clone();
    std::thread::Builder::new()
        .name("yany-capture".into())
        .spawn(move || capture_loop(cap, slot_c, ping_c))
        .context("capture thread")?;
    let mut encoder = ZstdTileCodec::default_realtime();
    let mut frame_seq = 1u64;
    let mut last_input_seq = 0u64;
    loop {
        if let Some(frame) = slot.take() {
            let tiles = encoder.encode(&frame)?;
            if tiles.tiles.is_empty() {
                continue;
            }
            let ciphertext = keys.seal_bincode(frame_seq, b"yany-frame", &tiles)?;
            send.send_msg(&ControlMsg::Frame { seq: frame_seq, ciphertext })
                .await?;
            frame_seq = frame_seq.wrapping_add(1);
            if frame_seq == 0 {
                frame_seq = 1;
            }
            continue;
        }
        tokio::select! {
            biased;
            msg = recv.recv_msg() => {
                match msg? {
                    ControlMsg::Input { seq, ciphertext } => {
                        if seq <= last_input_seq {
                            continue;
                        }
                        last_input_seq = seq;
                        let events: Vec<InputEvent> = keys.open_bincode(seq, b"yany-input", &ciphertext)?;
                        if events.len() > 64 {
                            bail!("input batch too large");
                        }
                        if let Err(e) = yany_input::inject(&events) {
                            tracing::warn!("inject: {e}");
                        }
                    }
                    ControlMsg::Disconnect { .. } => break,
                    other => bail!("unexpected host msg {other:?}"),
                }
            }
            _ = ping.notified() => {}
        }
    }
    Ok(())
}

pub async fn viewer_media<R, W>(
    mut reader: R,
    mut writer: W,
    keys: SessionKeys,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let slot = Arc::new(LatestSlot::new());
    let slot_r = slot.clone();
    let (input_tx, mut input_rx) = mpsc::channel::<Vec<InputEvent>>(8);
    let keys_read = keys.clone();
    let read_task = tokio::spawn(async move {
        let mut decoder = ZstdTileCodec::default_realtime();
        let mut last_frame_seq = 0u64;
        loop {
            match read_msg(&mut reader).await {
                Ok(ControlMsg::Frame { seq, ciphertext }) => {
                    if seq <= last_frame_seq {
                        continue;
                    }
                    last_frame_seq = seq;
                    let tiles: TileFrame =
                        keys_read.open_bincode(seq, b"yany-frame", &ciphertext)?;
                    let frame = decoder.decode(&tiles)?;
                    slot_r.push(frame);
                }
                Ok(ControlMsg::Disconnect { reason }) => {
                    tracing::info!("host disconnected: {reason}");
                    break;
                }
                Ok(ControlMsg::Error { message }) => bail!("session error: {message}"),
                Ok(other) => bail!("unexpected viewer msg {other:?}"),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    });

    let write_task = tokio::spawn(async move {
        let mut seq = 1u64;
        while let Some(events) = input_rx.recv().await {
            let ciphertext = keys.seal_bincode(seq, b"yany-input", &events)?;
            write_msg(&mut writer, &ControlMsg::Input { seq, ciphertext }).await?;
            seq = seq.wrapping_add(1);
            if seq == 0 {
                seq = 1;
            }
        }
        Ok::<_, anyhow::Error>(())
    });

    tokio::task::spawn_blocking(move || ui_loop(slot, input_tx)).await??;
    read_task.abort();
    write_task.abort();
    Ok(())
}

async fn viewer_media_udp(mut recv: UdpRecv, mut send: UdpSend, keys: SessionKeys) -> Result<()> {
    let slot = Arc::new(LatestSlot::new());
    let slot_r = slot.clone();
    let (input_tx, mut input_rx) = mpsc::channel::<Vec<InputEvent>>(8);
    let keys_read = keys.clone();
    let read_task = tokio::spawn(async move {
        let mut decoder = ZstdTileCodec::default_realtime();
        let mut last_frame_seq = 0u64;
        loop {
            match recv.recv_msg().await {
                Ok(ControlMsg::Frame { seq, ciphertext }) => {
                    if seq <= last_frame_seq {
                        continue;
                    }
                    last_frame_seq = seq;
                    let tiles: TileFrame =
                        keys_read.open_bincode(seq, b"yany-frame", &ciphertext)?;
                    slot_r.push(decoder.decode(&tiles)?);
                }
                Ok(ControlMsg::Disconnect { .. }) => break,
                Ok(other) => bail!("unexpected viewer msg {other:?}"),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    });
    let write_task = tokio::spawn(async move {
        let mut seq = 1u64;
        while let Some(events) = input_rx.recv().await {
            let ciphertext = keys.seal_bincode(seq, b"yany-input", &events)?;
            send.send_msg(&ControlMsg::Input { seq, ciphertext }).await?;
            seq = seq.wrapping_add(1);
            if seq == 0 {
                seq = 1;
            }
        }
        Ok::<_, anyhow::Error>(())
    });
    tokio::task::spawn_blocking(move || ui_loop(slot, input_tx)).await??;
    read_task.abort();
    write_task.abort();
    Ok(())
}

fn capture_loop(
    mut cap: Box<dyn CaptureBackend>,
    slot: Arc<LatestSlot<Frame>>,
    ping: Arc<tokio::sync::Notify>,
) {
    if let Err(e) = cap.start() {
        tracing::error!("capture start: {e}");
        return;
    }
    loop {
        match cap.next_frame() {
            Ok(Some(frame)) => {
                slot.push(frame);
                ping.notify_one();
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            Err(e) => {
                tracing::error!("capture: {e}");
                break;
            }
        }
    }
}

fn ui_loop(
    frames: Arc<LatestSlot<Frame>>,
    input_tx: mpsc::Sender<Vec<InputEvent>>,
) -> Result<()> {
    let mut window = Window::new(
        "Yany",
        1280,
        720,
        WindowOptions {
            resize: true,
            ..WindowOptions::default()
        },
    )?;
    window.set_target_fps(60);
    let mut buf = vec![0u32; 1280 * 720];
    let mut width = 1280usize;
    let mut height = 720usize;
    let mut prev_left = false;
    let mut prev_right = false;
    let mut prev_keys: Vec<Key> = Vec::new();
    let mut prev_mouse: Option<(u16, u16)> = None;

    while window.is_open() && !window.is_key_down(Key::Escape) {
        if let Some(frame) = frames.take() {
            width = frame.width as usize;
            height = frame.height as usize;
            if width > 0 && height > 0 {
                buf = bgra_to_u32(&frame.bgra);
                let _ = window.update_with_buffer(&buf, width, height);
            }
        }
        if buf.len() == width.saturating_mul(height) && width > 0 {
            let _ = window.update_with_buffer(&buf, width, height);
        } else {
            window.update();
        }

        let mut events = Vec::new();
        if let Some((mx, my)) = window.get_mouse_pos(MouseMode::Clamp) {
            let (ww, wh) = window.get_size();
            if ww > 1 && wh > 1 {
                let x = clamp_axis(((mx / (ww - 1) as f32) * 65535.0) as i32);
                let y = clamp_axis(((my / (wh - 1) as f32) * 65535.0) as i32);
                if prev_mouse != Some((x, y)) {
                    events.push(InputEvent::MouseMove { x, y });
                    prev_mouse = Some((x, y));
                }
            }
        }
        let left = window.get_mouse_down(MouseButton::Left);
        if left != prev_left {
            events.push(InputEvent::MouseButton {
                button: 0,
                down: left,
            });
            prev_left = left;
        }
        let right = window.get_mouse_down(MouseButton::Right);
        if right != prev_right {
            events.push(InputEvent::MouseButton {
                button: 1,
                down: right,
            });
            prev_right = right;
        }
        let held = window.get_keys();
        for key in &held {
            if !prev_keys.contains(key) {
                if let Some(vk) = map_key(*key) {
                    events.push(InputEvent::Key {
                        vk,
                        down: true,
                        scan: 0,
                    });
                }
            }
        }
        for key in &prev_keys {
            if !held.contains(key) {
                if let Some(vk) = map_key(*key) {
                    events.push(InputEvent::Key {
                        vk,
                        down: false,
                        scan: 0,
                    });
                }
            }
        }
        prev_keys = held;
        if !events.is_empty() {
            let _ = input_tx.try_send(events);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

fn bgra_to_u32(bgra: &[u8]) -> Vec<u32> {
    bgra.chunks_exact(4)
        .map(|c| {
            let b = c[0] as u32;
            let g = c[1] as u32;
            let r = c[2] as u32;
            (r << 16) | (g << 8) | b
        })
        .collect()
}

fn map_key(key: Key) -> Option<u16> {
    Some(match key {
        Key::Key0 => 0x30,
        Key::Key1 => 0x31,
        Key::Key2 => 0x32,
        Key::Key3 => 0x33,
        Key::Key4 => 0x34,
        Key::Key5 => 0x35,
        Key::Key6 => 0x36,
        Key::Key7 => 0x37,
        Key::Key8 => 0x38,
        Key::Key9 => 0x39,
        Key::A => 0x41,
        Key::B => 0x42,
        Key::C => 0x43,
        Key::D => 0x44,
        Key::E => 0x45,
        Key::F => 0x46,
        Key::G => 0x47,
        Key::H => 0x48,
        Key::I => 0x49,
        Key::J => 0x4A,
        Key::K => 0x4B,
        Key::L => 0x4C,
        Key::M => 0x4D,
        Key::N => 0x4E,
        Key::O => 0x4F,
        Key::P => 0x50,
        Key::Q => 0x51,
        Key::R => 0x52,
        Key::S => 0x53,
        Key::T => 0x54,
        Key::U => 0x55,
        Key::V => 0x56,
        Key::W => 0x57,
        Key::X => 0x58,
        Key::Y => 0x59,
        Key::Z => 0x5A,
        Key::Space => 0x20,
        Key::Enter => 0x0D,
        Key::Tab => 0x09,
        Key::Backspace => 0x08,
        Key::LeftShift | Key::RightShift => 0x10,
        Key::LeftCtrl | Key::RightCtrl => 0x11,
        Key::LeftAlt | Key::RightAlt => 0x12,
        Key::Up => 0x26,
        Key::Down => 0x28,
        Key::Left => 0x25,
        Key::Right => 0x27,
        Key::Delete => 0x2E,
        Key::Home => 0x24,
        Key::End => 0x23,
        _ => return None,
    })
}
