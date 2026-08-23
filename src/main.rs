use clap::{Parser, Subcommand};
use gatekeeper::{password, token};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "gatekeeper", version, about = "A from-scratch token authentication toolkit.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Issue a signed token for a subject.
    Issue {
        #[arg(long)]
        sub: String,
        #[arg(long)]
        ttl: u64,
        #[arg(long)]
        secret: String,
    },
    /// Verify a signed token.
    Verify {
        token: String,
        #[arg(long)]
        secret: String,
    },
    /// Hash a password.
    Hash { password: String },
    /// Check a password against a hash.
    Check { password: String, hash: String },
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Issue { sub, ttl, secret } => {
            match token::issue(&sub, ttl, secret.as_bytes(), now_secs()) {
                Ok(t) => {
                    println!("{}", t);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        Command::Verify { token: t, secret } => {
            match token::verify(&t, secret.as_bytes(), now_secs()) {
                Ok(claims) => {
                    println!("valid");
                    println!("sub: {}", claims.sub);
                    println!("iat: {}", claims.iat);
                    println!("exp: {}", claims.exp);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    println!("invalid: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
        Command::Hash { password: p } => match password::hash(&p) {
            Ok(h) => {
                println!("{}", h);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {}", e);
                ExitCode::FAILURE
            }
        },
        Command::Check { password: p, hash } => match password::check(&p, &hash) {
            Ok(true) => {
                println!("match");
                ExitCode::SUCCESS
            }
            Ok(false) => {
                println!("no match");
                ExitCode::FAILURE
            }
            Err(e) => {
                eprintln!("error: {}", e);
                ExitCode::FAILURE
            }
        },
    }
}
