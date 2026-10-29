use anyhow::Result;
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use yany_core::join_token::JoinSecret;

mod server;
mod tls;

#[derive(Parser, Debug)]
#[command(name = "yany-relay")]
struct Args {
    /// Listen address.
    #[arg(long, env = "YANY_RELAY_BIND", default_value = "0.0.0.0:6568")]
    bind: SocketAddr,
    #[arg(long, env = "YANY_TLS_CERT")]
    cert: Option<PathBuf>,
    #[arg(long, env = "YANY_TLS_KEY")]
    key: Option<PathBuf>,
    /// Write a self-signed cert for first bring-up. Replace with Let's Encrypt in production.
    #[arg(long)]
    dev_cert_dir: Option<PathBuf>,
    #[arg(long, env = "YANY_JOIN_TOKEN_FILE")]
    token_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print the current join token (use after SSH: docker exec ... yany-relay token).
    Token,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let args = Args::parse();
    let cert_dir = args
        .dev_cert_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("./tls"));
    let token_file = args
        .token_file
        .clone()
        .unwrap_or_else(|| cert_dir.join("join.token"));
    if matches!(args.command, Some(Command::Token)) {
        match JoinSecret::read_file(&token_file) {
            Ok(secret) => {
                print!("{}", secret.cli_report());
                return Ok(());
            }
            Err(e) => anyhow::bail!(
                "join token okunamadı ({}): {e} — yany-relay çalışıyor mu?",
                token_file.display()
            ),
        }
    }
    let (cert, key, fp) = if let (Some(c), Some(k)) = (args.cert.clone(), args.key.clone()) {
        let fp = tls::fingerprint_file(&c)?;
        (c, k, fp)
    } else {
        tls::load_or_create_dev_cert(&cert_dir)?
    };
    tracing::warn!("TLS fingerprint {fp} — pin this on clients with --fingerprint");
    server::run(args.bind, cert, key, token_file).await
}
