mod cli;
mod crypto;

use anyhow::Result;
use colored::Colorize;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{} {}", "error:".red().bold(), err);
            for cause in err.chain().skip(1) {
                eprintln!("  {} {}", "cause:".dimmed(), cause);
            }
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    cli::run()
}
