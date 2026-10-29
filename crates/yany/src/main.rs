mod agent;
mod config;
mod host;
mod identity;
mod password;
mod session;
mod tls_client;
mod ui;
mod view;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "yany")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    Host(host::Args),
    View(view::Args),
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    match Cli::parse().cmd {
        Some(Cmd::Host(args)) => {
            tokio::runtime::Runtime::new()?.block_on(host::run(args))
        }
        Some(Cmd::View(args)) => {
            tokio::runtime::Runtime::new()?.block_on(view::run(args))
        }
        None => ui::run(),
    }
}
