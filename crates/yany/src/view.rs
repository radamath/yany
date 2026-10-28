use crate::password;
use crate::tls_client;
use anyhow::{bail, Result};
use clap::Parser;
use minifb::{Key, MouseButton, MouseMode, Window, WindowOptions};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::split;
use tokio::sync::mpsc;
use yany_core::capture::Frame;
use yany_core::crypto::SessionKeys;
use yany_core::encode::{FrameDecoder, ZstdTileCodec};
use yany_core::framing::{read_control, read_msg, write_msg};
use yany_core::id::HostId;
use yany_core::input::{clamp_axis, InputEvent};
use yany_core::protocol::{ControlMsg, Role, PROTOCOL_VERSION};
use yany_core::tile::TileFrame;

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(long, env = "YANY_RELAY")]
    relay: String,
    #[arg(long, env = "YANY_TLS_FINGERPRINT")]
    fingerprint: String,
    #[arg(long, env = "YANY_PASSWORD_FILE")]
    password_file: PathBuf,
    #[arg(long)]
    host: String,
}

pub async fn run(args: Args) -> Result<()> {
    let target: HostId = args.host.parse()?;
    let password = password::load(&args.password_file)?;
    let tls = tls_client::connect(&args.relay, &args.fingerprint).await?;
    let (mut reader, mut writer) = split(tls);
    write_msg(
        &mut writer,
        &ControlMsg::Hello {
            version: PROTOCOL_VERSION,
            role: Role::Viewer,
        },
    )
    .await?;
    write_msg(&mut writer, &ControlMsg::Connect { target }).await?;

    let challenge = match read_control(&mut reader).await? {
        ControlMsg::Challenge { nonce } => nonce,
        ControlMsg::Error { message } => bail!("relay: {message}"),
        other => bail!("expected challenge, got {other:?}"),
    };
    let keys = SessionKeys::derive(&password, &challenge, false)?;
    let proof = SessionKeys::auth_proof(&password, &challenge)?;
    write_msg(&mut writer, &ControlMsg::Auth { proof }).await?;
    match read_control(&mut reader).await? {
        ControlMsg::AuthOk => {}
        ControlMsg::AuthFail => bail!("authentication failed"),
        ControlMsg::Error { message } => bail!("relay: {message}"),
        other => bail!("expected AuthOk, got {other:?}"),
    }

    let (frame_tx, frame_rx) = std::sync::mpsc::sync_channel::<Frame>(1);
    let (input_tx, mut input_rx) = mpsc::channel::<Vec<InputEvent>>(8);
    let keys_read = keys.clone();
    let read_task = tokio::spawn(async move {
        let mut decoder = ZstdTileCodec::default_realtime();
        let mut last_frame_seq = 0u64;
        loop {
            match read_msg(&mut reader).await {
                Ok(ControlMsg::Frame { seq, ciphertext }) => {
                    if seq <= last_frame_seq {
                        bail!("replayed frame seq {seq}");
                    }
                    last_frame_seq = seq;
                    let tiles: TileFrame =
                        keys_read.open_bincode(seq, b"yany-frame", &ciphertext)?;
                    let frame = decoder.decode(&tiles)?;
                    let _ = frame_tx.send(frame);
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

    tokio::task::spawn_blocking(move || ui_loop(frame_rx, input_tx)).await??;
    read_task.abort();
    write_task.abort();
    Ok(())
}

fn ui_loop(
    frames: std::sync::mpsc::Receiver<Frame>,
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

    while window.is_open() && !window.is_key_down(Key::Escape) {
        while let Ok(frame) = frames.try_recv() {
            width = frame.width as usize;
            height = frame.height as usize;
            if width == 0 || height == 0 {
                continue;
            }
            buf = bgra_to_u32(&frame.bgra);
            let _ = window.update_with_buffer(&buf, width, height);
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
                events.push(InputEvent::MouseMove { x, y });
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
            let _ = input_tx.blocking_send(events);
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
