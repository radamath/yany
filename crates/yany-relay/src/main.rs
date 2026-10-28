use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

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
    let (cert, key, fp) = if let (Some(c), Some(k)) = (args.cert.clone(), args.key.clone()) {
        let fp = tls::fingerprint_file(&c)?;
        (c, k, fp)
    } else {
        let dir = args
            .dev_cert_dir
            .unwrap_or_else(|| PathBuf::from("./tls"));
        tls::load_or_create_dev_cert(&dir)?
    };
    tracing::warn!("TLS fingerprint {fp} — pin this on clients with --fingerprint");
    server::run(args.bind, cert, key).await
}
