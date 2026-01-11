use anyhow::{bail, Result};

/// Parse a 64-character hex string into a 32-byte key
pub fn parse_hex_key(hex: &str) -> Result<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        bail!(
            "Encryption key must be 64 hex characters (32 bytes), got {} characters",
            hex.len()
        );
    }

    let mut key = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hex_str = std::str::from_utf8(chunk)?;
        key[i] = u8::from_str_radix(hex_str, 16)
            .map_err(|_| anyhow::anyhow!("Invalid hex character in encryption key"))?;
    }
    Ok(key)
}
