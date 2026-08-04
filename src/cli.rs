use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use rpassword::prompt_password;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::crypto;

#[derive(Parser)]
#[command(
    name = "fenc",
    version,
    about = "Encrypt and decrypt files using AES-256-GCM with Argon2id key derivation",
    long_about = "Streaming, chunked AES-256-GCM file encryption with Argon2id-derived keys. \
                  Supports single files and batch mode over a directory. Progress is printed \
                  to stderr so encrypted output can be piped or scripted freely."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Encrypt {
        input: Option<PathBuf>,
        #[arg(long, short)]
        output: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        keep: bool,
        #[arg(long)]
        force: bool,
    },
    Decrypt {
        input: Option<PathBuf>,
        #[arg(long, short)]
        output: Option<PathBuf>,
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        keep: bool,
        #[arg(long)]
        force: bool,
    },
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Encrypt {
            input,
            output,
            dir,
            keep,
            force,
        } => encrypt_dispatch(input, output, dir, keep, force),
        Command::Decrypt {
            input,
            output,
            dir,
            keep,
            force,
        } => decrypt_dispatch(input, output, dir, keep, force),
    }
}

fn encrypt_dispatch(
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    dir: Option<PathBuf>,
    keep: bool,
    force: bool,
) -> Result<()> {
    let password = prompt_password_confirmed()?;
    if let Some(dir) = dir {
        return batch_encrypt(&dir, &password, keep, force);
    }
    let input =
        input.ok_or_else(|| anyhow!("Provide an input file path or use --dir <DIRECTORY>"))?;
    if !input.is_file() {
        return Err(anyhow!(
            "Input path is not a regular file: {}",
            input.display()
        ));
    }
    let output = output.unwrap_or_else(|| append_ext(&input, "enc"));
    ensure_output_ok(&output, force)?;
    do_encrypt(&input, &output, &password, keep)
}

fn decrypt_dispatch(
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    dir: Option<PathBuf>,
    keep: bool,
    force: bool,
) -> Result<()> {
    let password = Zeroizing::new(prompt_password(color_prompt("Password"))?);
    if let Some(dir) = dir {
        return batch_decrypt(&dir, &password, keep, force);
    }
    let input =
        input.ok_or_else(|| anyhow!("Provide an input file path or use --dir <DIRECTORY>"))?;
    if !input.is_file() {
        return Err(anyhow!(
            "Input path is not a regular file: {}",
            input.display()
        ));
    }
    let output = output.unwrap_or_else(|| default_decrypt_output(&input));
    ensure_output_ok(&output, force)?;
    do_decrypt(&input, &output, &password, keep)
}

fn do_encrypt(input: &Path, output: &Path, password: &str, keep: bool) -> Result<()> {
    println!(
        "{} {} {} {}",
        "[enc]".cyan().bold(),
        input.display().to_string().bright_white(),
        "->".dimmed(),
        output.display().to_string().bright_white()
    );
    crypto::encrypt_stream(input, output, password)?;
    println!("{} Encrypted successfully.", "[+]".green().bold());
    if !keep {
        if let Err(e) = fs::remove_file(input) {
            eprintln!(
                "{} Could not remove original {}: {}",
                "warn:".yellow(),
                input.display(),
                e
            );
        } else {
            println!(
                "{} Removed original: {}",
                "[*]".dimmed(),
                input.display()
            );
        }
    }
    Ok(())
}

fn do_decrypt(input: &Path, output: &Path, password: &str, keep: bool) -> Result<()> {
    println!(
        "{} {} {} {}",
        "[dec]".magenta().bold(),
        input.display().to_string().bright_white(),
        "->".dimmed(),
        output.display().to_string().bright_white()
    );
    crypto::decrypt_stream(input, output, password)?;
    println!("{} Decrypted successfully.", "[+]".green().bold());
    if !keep {
        if let Err(e) = fs::remove_file(input) {
            eprintln!(
                "{} Could not remove encrypted file {}: {}",
                "warn:".yellow(),
                input.display(),
                e
            );
        } else {
            println!(
                "{} Removed encrypted file: {}",
                "[*]".dimmed(),
                input.display()
            );
        }
    }
    Ok(())
}

fn batch_encrypt(dir: &Path, password: &str, keep: bool, force: bool) -> Result<()> {
    if !dir.is_dir() {
        return Err(anyhow!("--dir must point to a directory: {}", dir.display()));
    }
    let entries = collect_files(dir)?;
    let mut processed = 0;
    for path in entries {
        if path.extension().and_then(|e| e.to_str()) == Some("enc") {
            continue;
        }
        let output = append_ext(&path, "enc");
        if let Err(e) = ensure_output_ok(&output, force) {
            eprintln!("{} {}: {}", "skip:".yellow(), path.display(), e);
            continue;
        }
        do_encrypt(&path, &output, password, keep)?;
        processed += 1;
    }
    println!(
        "{} Batch encryption complete: {} file(s) processed.",
        "[+]".green().bold(),
        processed
    );
    Ok(())
}

fn batch_decrypt(dir: &Path, password: &str, keep: bool, force: bool) -> Result<()> {
    if !dir.is_dir() {
        return Err(anyhow!("--dir must point to a directory: {}", dir.display()));
    }
    let entries = collect_files(dir)?;
    let mut processed = 0;
    for path in entries {
        if path.extension().and_then(|e| e.to_str()) != Some("enc") {
            continue;
        }
        let output = default_decrypt_output(&path);
        if let Err(e) = ensure_output_ok(&output, force) {
            eprintln!("{} {}: {}", "skip:".yellow(), path.display(), e);
            continue;
        }
        do_decrypt(&path, &output, password, keep)?;
        processed += 1;
    }
    println!(
        "{} Batch decryption complete: {} file(s) processed.",
        "[+]".green().bold(),
        processed
    );
    Ok(())
}

fn collect_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn prompt_password_confirmed() -> Result<Zeroizing<String>> {
    let a = Zeroizing::new(prompt_password(color_prompt("Password"))?);
    if a.len() < 8 {
        return Err(anyhow!("Password must be at least 8 characters"));
    }
    let b = Zeroizing::new(prompt_password(color_prompt("Confirm password"))?);
    if a.as_str() != b.as_str() {
        return Err(anyhow!("Passwords do not match"));
    }
    Ok(a)
}

fn color_prompt(label: &str) -> String {
    format!("{}: ", label.cyan())
}

fn append_ext(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

fn default_decrypt_output(path: &Path) -> PathBuf {
    if path.extension().and_then(|e| e.to_str()) == Some("enc") {
        path.with_extension("")
    } else {
        append_ext(path, "dec")
    }
}

fn ensure_output_ok(output: &Path, force: bool) -> Result<()> {
    if output.exists() && !force {
        return Err(anyhow!(
            "Output already exists: {} (pass --force to overwrite)",
            output.display()
        ));
    }
    Ok(())
}
