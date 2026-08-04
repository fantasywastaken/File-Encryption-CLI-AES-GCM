# fenc — Streaming File Encryption CLI (AES-256-GCM + Argon2id)

`fenc` is a small, fast, no-nonsense Rust CLI for encrypting and decrypting files on disk. It streams data in 64 KiB chunks so it comfortably handles multi-gigabyte files without loading them into memory, and it uses **AES-256-GCM** (an authenticated cipher) with **Argon2id** for password-based key derivation.

## Features

- Streaming AES-256-GCM: each 64 KiB chunk is encrypted independently with a fresh random nonce.
- Argon2id KDF (m=19456 KiB, t=2, p=1) with 128-bit random salt per file.
- Single-file mode and batch (`--dir`) mode.
- Live progress bar rendered to stderr (safe to redirect stdout).
- Atomic file header with magic bytes and version for forward compatibility.
- In-memory zeroization of derived keys and working buffers via `zeroize`.
- Refuses to overwrite existing outputs unless `--force` is passed.
- Optionally removes the source file after a successful conversion (default) or preserves it with `--keep`.
- Hidden password prompts through `rpassword`.
- Cross-platform (Linux, macOS, Windows).

## File format

```
Header (37 bytes total):
  offset 0  : magic bytes  "FENC"          (4)
  offset 4  : version byte  0x01           (1)
  offset 5  : chunk_size    u32 little-endian (4)
  offset 9  : salt          16 random bytes (16)

Repeating chunk records until EOF:
  nonce     : 12 random bytes
  ct_len    : u32 little-endian (length of encrypted_chunk in bytes)
  encrypted_chunk : ct_len bytes = ciphertext + 16-byte GCM tag
```

Each chunk carries its own GCM authentication tag, so any modification, truncation, or bit flip produces a hard decryption failure with a helpful error message.

## Cryptographic design

| Layer               | Choice                                                         |
| ------------------- | -------------------------------------------------------------- |
| KDF                 | Argon2id, m=19456 KiB, t=2, p=1, output 32 bytes               |
| Salt                | 16 bytes from `OsRng` (per file)                               |
| Cipher              | AES-256-GCM (256-bit key, 96-bit nonce, 128-bit tag)           |
| Nonce               | 12 bytes from `OsRng` (per chunk, never reused with same key)  |
| Chunk size          | 65 536 bytes (64 KiB)                                          |

## Installation

```bash
git clone <this-repo>
cd File-Encryption-CLI-AES-GCM
cargo build --release
# The binary is at target/release/fenc
```

## Quick start

```bash
# Encrypt one file (creates secrets.txt.enc, removes secrets.txt)
fenc encrypt secrets.txt

# Encrypt but keep the original around
fenc encrypt secrets.txt --keep

# Choose a specific output path
fenc encrypt secrets.txt --output vault.bin

# Decrypt back to a plaintext file (creates secrets.txt from secrets.txt.enc)
fenc decrypt secrets.txt.enc

# Batch encrypt every file in a directory (except *.enc files)
fenc encrypt --dir ./secrets

# Batch decrypt every *.enc file in a directory
fenc decrypt --dir ./secrets

# Overwrite existing outputs
fenc encrypt secrets.txt --output vault.bin --force
```

## Commands

### `fenc encrypt`

Encrypts a single file or a whole directory.

```
fenc encrypt <INPUT>          [--output <PATH>]
fenc encrypt --dir <DIR>
             [--keep]          Do not remove source files after success
             [--force]         Overwrite outputs that already exist
```

### `fenc decrypt`

Decrypts a single `.enc` file or a whole directory of them.

```
fenc decrypt <INPUT>          [--output <PATH>]
fenc decrypt --dir <DIR>
             [--keep]          Do not remove the .enc source after success
             [--force]         Overwrite outputs that already exist
```

## Progress output

Progress bars are written to **stderr** as the encryption proceeds:

```
[enc] my-big.bin -> my-big.bin.enc
[enc] [============================>  ]  92.34%  92.34 MB / 100.00 MB
[+] Encrypted successfully.
```

This means you can redirect stdout freely (`fenc encrypt foo > log.txt`) without losing the progress display.

## Security notes

- **Do not lose your password.** There is no recovery path.
- Use a strong password (16+ chars) or a diceware passphrase. Argon2id makes brute force expensive but not free.
- The encrypted file is safe to sync, share, or back up publicly — without the password it is opaque ciphertext.
- Each chunk gets its own random 96-bit nonce; the tag verifies both ciphertext and (implicitly) chunk order, since a decryption error will occur if chunks are shuffled.

## Exit codes

| Code | Meaning                                       |
| ---- | --------------------------------------------- |
| 0    | Success                                       |
| 1    | Error (bad password, corrupted file, I/O, …)  |

## License

MIT.
