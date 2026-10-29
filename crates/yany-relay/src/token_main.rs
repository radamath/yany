use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use yany_core::join_token::JoinSecret;

#[derive(Parser, Debug)]
#[command(name = "yany-token")]
struct Args {
    #[arg(long, env = "YANY_JOIN_TOKEN_FILE", default_value = "/data/tls/join.token")]
    file: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    match JoinSecret::read_file(&args.file) {
        Ok(secret) => {
            print!("{}", secret.cli_report());
            Ok(())
        }
        Err(e) => anyhow::bail!(
            "join token okunamadı ({}): {e} — yany-relay çalışıyor mu?",
            args.file.display()
        ),
    }
}
