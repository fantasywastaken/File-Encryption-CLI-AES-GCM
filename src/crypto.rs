use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use colored::Colorize;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use zeroize::Zeroize;

pub const MAGIC: &[u8; 4] = b"FENC";
pub const FORMAT_VERSION: u8 = 1;
pub const CHUNK_SIZE: usize = 64 * 1024;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(19_456, 2, 1, Some(KEY_LEN))
        .map_err(|e| anyhow!("Argon2 params error: {}", e))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Argon2 KDF failed: {}", e))?;
    Ok(key)
}

pub fn encrypt_stream(input: &Path, output: &Path, password: &str) -> Result<()> {
    let file_size = std::fs::metadata(input)
        .with_context(|| format!("Failed to stat input {}", input.display()))?
        .len();

    let in_file = File::open(input)
        .with_context(|| format!("Failed to open input {}", input.display()))?;
    let mut reader = BufReader::new(in_file);

    let out_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output)
        .with_context(|| format!("Failed to open output {}", output.display()))?;
    let mut writer = BufWriter::new(out_file);

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("Cipher initialization failed: {}", e))?;

    writer.write_all(MAGIC)?;
    writer.write_all(&[FORMAT_VERSION])?;
    writer.write_all(&(CHUNK_SIZE as u32).to_le_bytes())?;
    writer.write_all(&salt)?;

    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut done: u64 = 0;
    loop {
        let n = read_up_to(&mut reader, &mut buf)?;
        if n == 0 {
            break;
        }
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, &buf[..n])
            .map_err(|_| anyhow!("Failed to encrypt chunk"))?;
        writer.write_all(&nonce_bytes)?;
        writer.write_all(&(ciphertext.len() as u32).to_le_bytes())?;
        writer.write_all(&ciphertext)?;
        done += n as u64;
        print_progress("enc", done, file_size);
    }
    writer.flush()?;
    key.zeroize();
    buf.zeroize();
    finish_progress_line();
    Ok(())
}

pub fn decrypt_stream(input: &Path, output: &Path, password: &str) -> Result<()> {
    let file_size = std::fs::metadata(input)
        .with_context(|| format!("Failed to stat input {}", input.display()))?
        .len();

    let in_file = File::open(input)
        .with_context(|| format!("Failed to open input {}", input.display()))?;
    let mut reader = BufReader::new(in_file);

    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(anyhow!(
            "Not a valid FENC file (bad magic bytes: {:02X?})",
            magic
        ));
    }
    let mut version_buf = [0u8; 1];
    reader.read_exact(&mut version_buf)?;
    if version_buf[0] != FORMAT_VERSION {
        return Err(anyhow!(
            "Unsupported file format version {}",
            version_buf[0]
        ));
    }
    let mut chunk_size_buf = [0u8; 4];
    reader.read_exact(&mut chunk_size_buf)?;
    let chunk_size = u32::from_le_bytes(chunk_size_buf) as usize;
    if chunk_size == 0 || chunk_size > 16 * 1024 * 1024 {
        return Err(anyhow!("Refusing to process suspicious chunk size {}", chunk_size));
    }

    let mut salt = [0u8; SALT_LEN];
    reader.read_exact(&mut salt)?;

    let mut key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow!("Cipher initialization failed: {}", e))?;

    let out_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(output)
        .with_context(|| format!("Failed to open output {}", output.display()))?;
    let mut writer = BufWriter::new(out_file);

    let mut consumed: u64 = 4 + 1 + 4 + SALT_LEN as u64;
    loop {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        match reader.read_exact(&mut nonce_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let ct_len = u32::from_le_bytes(len_buf) as usize;
        if ct_len == 0 || ct_len > chunk_size + TAG_LEN + 64 {
            return Err(anyhow!("Refusing chunk with invalid length {}", ct_len));
        }
        let mut ct = vec![0u8; ct_len];
        reader.read_exact(&mut ct)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plain = cipher
            .decrypt(nonce, ct.as_slice())
            .map_err(|_| anyhow!("Decryption failed: wrong password or corrupted data"))?;
        writer.write_all(&plain)?;
        consumed += (NONCE_LEN + 4 + ct_len) as u64;
        print_progress("dec", consumed, file_size);
    }
    writer.flush()?;
    key.zeroize();
    finish_progress_line();
    Ok(())
}

fn read_up_to(reader: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut read = 0;
    while read < buf.len() {
        match reader.read(&mut buf[read..])? {
            0 => break,
            n => read += n,
        }
    }
    Ok(read)
}

fn print_progress(tag: &str, done: u64, total: u64) {
    let (bar, pct) = build_bar(done, total, 30);
    let colored_tag = match tag {
        "enc" => tag.cyan().bold(),
        "dec" => tag.magenta().bold(),
        _ => tag.normal(),
    };
    eprint!(
        "\r[{}] [{}] {:>6.2}%  {} / {}",
        colored_tag,
        bar,
        pct,
        format_bytes(done),
        format_bytes(total)
    );
    let _ = std::io::stderr().flush();
}

fn build_bar(done: u64, total: u64, width: usize) -> (String, f64) {
    if total == 0 {
        return ("=".repeat(width), 100.0);
    }
    let pct = ((done as f64) / (total as f64) * 100.0).min(100.0);
    let filled = ((pct / 100.0) * width as f64) as usize;
    let mut s = String::with_capacity(width);
    for i in 0..width {
        if i < filled {
            s.push('=');
        } else if i == filled {
            s.push('>');
        } else {
            s.push(' ');
        }
    }
    (s, pct)
}

fn finish_progress_line() {
    eprintln!();
}

pub fn format_bytes(b: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * KB;
    const GB: f64 = 1024.0 * MB;
    let x = b as f64;
    if x >= GB {
        format!("{:>7.2} GB", x / GB)
    } else if x >= MB {
        format!("{:>7.2} MB", x / MB)
    } else if x >= KB {
        format!("{:>7.2} KB", x / KB)
    } else {
        format!("{:>7} B ", b)
    }
}
