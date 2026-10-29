use crate::password;
use crate::session;
use crate::tls_client;
use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tokio::io::split;
use yany_core::framing::write_msg;
use yany_core::id::HostId;
use yany_core::protocol::{ControlMsg, Role, PROTOCOL_VERSION};

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
    let (reader, mut writer) = split(tls);
    write_msg(
        &mut writer,
        &ControlMsg::Hello {
            version: PROTOCOL_VERSION,
            role: Role::Viewer,
        },
    )
    .await?;
    write_msg(&mut writer, &ControlMsg::Connect { target }).await?;
    session::viewer_handshake_and_media(reader, writer, &password).await
}
