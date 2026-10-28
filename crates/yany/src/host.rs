use crate::identity;
use crate::password;
use crate::tls_client;
use anyhow::{bail, Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::split;
use yany_capture::open_capture;
use yany_core::auth::random_bytes;
use yany_core::capture::{CaptureBackend, Frame};
use yany_core::config::CaptureKind;
use yany_core::crypto::SessionKeys;
use yany_core::encode::{FrameEncoder, ZstdTileCodec};
use yany_core::framing::{read_control, read_msg, write_msg};
use yany_core::input::InputEvent;
use yany_core::protocol::{ControlMsg, Role, PROTOCOL_VERSION};

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(long, env = "YANY_RELAY")]
    relay: String,
    #[arg(long, env = "YANY_TLS_FINGERPRINT")]
    fingerprint: String,
    #[arg(long, env = "YANY_PASSWORD_FILE")]
    password_file: Option<PathBuf>,
    #[arg(long, env = "YANY_CAPTURE", default_value = "dxgi")]
    capture: String,
    #[arg(long)]
    id_file: Option<PathBuf>,
    #[arg(long)]
    write_password: bool,
}

pub async fn run(args: Args) -> Result<()> {
    let kind = CaptureKind::parse(&args.capture)?;
    let dir = identity::data_dir();
    let password_file = args
        .password_file
        .unwrap_or_else(|| dir.join("host.password"));
    let id_file = args.id_file.unwrap_or_else(|| dir.join("host.id"));
    let password = if args.write_password {
        password::write_random(&password_file)?
    } else {
        password::require_file(&password_file)?
    };
    let id = identity::load_or_create_id(&id_file)?;
    let cap = open_capture(kind).with_context(|| {
        format!(
            "capture backend '{}' failed — try --capture gdi",
            kind.as_str()
        )
    })?;
    tracing::info!("capture backend {}", cap.kind().as_str());
    println!("Yany host id: {id}");
    println!("password file: {}", password_file.display());

    let tls = tls_client::connect(&args.relay, &args.fingerprint).await?;
    let (mut reader, mut writer) = split(tls);
    write_msg(
        &mut writer,
        &ControlMsg::Hello {
            version: PROTOCOL_VERSION,
            role: Role::Host,
        },
    )
    .await?;
    write_msg(&mut writer, &ControlMsg::RegisterHost { id }).await?;
    match read_control(&mut reader).await? {
        ControlMsg::RegisterOk { id: got } if got == id => {}
        ControlMsg::Error { message } => bail!("relay: {message}"),
        other => bail!("unexpected register reply: {other:?}"),
    }
    tracing::info!("registered, waiting for viewer");
    match read_control(&mut reader).await? {
        ControlMsg::Incoming => {}
        ControlMsg::Error { message } => bail!("relay: {message}"),
        other => bail!("unexpected wait reply: {other:?}"),
    }

    let nonce = random_bytes::<32>();
    write_msg(&mut writer, &ControlMsg::Challenge { nonce }).await?;
    let keys = SessionKeys::derive(&password, &nonce, true)?;
    match read_control(&mut reader).await? {
        ControlMsg::Auth { proof } => keys.verify_auth_proof(&proof)?,
        ControlMsg::Disconnect { reason } => bail!("viewer left: {reason}"),
        other => bail!("expected auth, got {other:?}"),
    }
    write_msg(&mut writer, &ControlMsg::AuthOk).await?;

    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel::<Frame>(2);
    std::thread::Builder::new()
        .name("yany-capture".into())
        .spawn(move || capture_loop(cap, frame_tx))
        .context("capture thread")?;

    let mut encoder = ZstdTileCodec::default_realtime();
    let mut frame_seq = 1u64;
    let mut last_input_seq = 0u64;
    loop {
        tokio::select! {
            frame = frame_rx.recv() => {
                let Some(frame) = frame else { break; };
                let tiles = encoder.encode(&frame)?;
                let ciphertext = keys.seal_bincode(frame_seq, b"yany-frame", &tiles)?;
                write_msg(&mut writer, &ControlMsg::Frame { seq: frame_seq, ciphertext }).await?;
                frame_seq = frame_seq.wrapping_add(1);
                if frame_seq == 0 {
                    frame_seq = 1;
                }
            }
            msg = read_msg(&mut reader) => {
                match msg? {
                    ControlMsg::Input { seq, ciphertext } => {
                        if seq <= last_input_seq {
                            bail!("replayed input seq {seq}");
                        }
                        last_input_seq = seq;
                        let events: Vec<InputEvent> = keys.open_bincode(seq, b"yany-input", &ciphertext)?;
                        if events.len() > 64 {
                            bail!("input batch too large");
                        }
                        yany_input::inject(&events)?;
                    }
                    ControlMsg::Disconnect { reason } => {
                        tracing::info!("viewer disconnected: {reason}");
                        break;
                    }
                    ControlMsg::Error { message } => bail!("session error: {message}"),
                    other => bail!("unexpected host msg {other:?}"),
                }
            }
        }
    }
    Ok(())
}

fn capture_loop(mut cap: Box<dyn CaptureBackend>, tx: tokio::sync::mpsc::Sender<Frame>) {
    if let Err(e) = cap.start() {
        tracing::error!("capture start: {e}");
        return;
    }
    loop {
        match cap.next_frame() {
            Ok(Some(frame)) => {
                if tx.blocking_send(frame).is_err() {
                    break;
                }
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            Err(e) => {
                tracing::error!("capture: {e}");
                break;
            }
        }
    }
}
