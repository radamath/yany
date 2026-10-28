mod host;
mod identity;
mod password;
mod tls_client;
mod view;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "yany")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    Host(host::Args),
    View(view::Args),
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    match Cli::parse().cmd {
        Cmd::Host(args) => host::run(args).await,
        Cmd::View(args) => view::run(args).await,
    }
}
