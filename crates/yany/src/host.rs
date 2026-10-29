use crate::identity;
use crate::password;
use crate::session;
use crate::tls_client;
use anyhow::{bail, Result};
use clap::Parser;
use std::path::PathBuf;
use tokio::io::split;
use yany_core::config::CaptureKind;
use yany_core::framing::{read_control, write_msg};
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
    session::host_handshake_and_media(reader, writer, &password, kind).await
}
