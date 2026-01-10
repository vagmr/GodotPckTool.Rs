//! AES-256-CFB encryption/decryption support for Godot 4 encrypted PCK files.
//!
//! Godot 4 uses AES-256-CFB mode for encrypting PCK files.
//! Each encrypted block has a 40-byte header: MD5(16) + original_size(8) + IV(16)

use aes::Aes256;
use aes::cipher::AsyncStreamCipher;
use cfb_mode::Decryptor;
use cfb_mode::cipher::KeyIvInit;
use anyhow::{Result, bail};

type Aes256CfbDec = Decryptor<Aes256>;

/// Encrypted block header size: MD5(16) + original_size(8) + IV(16) = 40 bytes
pub const ENCRYPTED_HEADER_SIZE: usize = 40;

/// Parsed encrypted block header
#[derive(Debug, Clone)]
pub struct EncryptedHeader {
    /// MD5 hash of the original (unencrypted) data
    pub md5: [u8; 16],
    /// Original data size before encryption
    pub original_size: u64,
    /// Initialization vector for AES-CFB
    pub iv: [u8; 16],
}

impl EncryptedHeader {
    /// Parse encrypted header from raw bytes
    ///
    /// # Layout (40 bytes total)
    /// - Bytes 0-15: MD5 hash
    /// - Bytes 16-23: Original size (i64 little-endian)
    /// - Bytes 24-39: IV
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < ENCRYPTED_HEADER_SIZE {
            bail!(
                "Encrypted header too short: expected {} bytes, got {}",
                ENCRYPTED_HEADER_SIZE,
                data.len()
            );
        }

        let mut md5 = [0u8; 16];
        md5.copy_from_slice(&data[0..16]);

        let original_size_i64 = i64::from_le_bytes(data[16..24].try_into()?);
        if original_size_i64 < 0 {
            bail!(
                "Encrypted header original size is negative: {}",
                original_size_i64
            );
        }
        let original_size = original_size_i64 as u64;

        let mut iv = [0u8; 16];
        iv.copy_from_slice(&data[24..40]);

        Ok(Self {
            md5,
            original_size,
            iv,
        })
    }
}

/// Decrypt data using AES-256-CFB mode
///
/// # Arguments
/// * `data` - Encrypted data (must be aligned to 16 bytes)
/// * `key` - 32-byte encryption key
/// * `iv` - 16-byte initialization vector
///
/// # Returns
/// Decrypted data (same length as input)
pub fn decrypt_cfb(data: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    let decryptor = Aes256CfbDec::new(key.into(), iv.into());
    let mut buffer = data.to_vec();
    decryptor.decrypt(&mut buffer);
    buffer
}

/// Align size to 16-byte boundary (AES block size)
#[inline]
pub fn align_to_16(size: u64) -> u64 {
    (size + 15) & !15
}

/// Verify MD5 hash of decrypted data
///
/// # Arguments
/// * `data` - Decrypted data to verify
/// * `expected_md5` - Expected MD5 hash from encrypted header
///
/// # Returns
/// `true` if MD5 matches, `false` otherwise
pub fn verify_md5(data: &[u8], expected_md5: &[u8; 16]) -> bool {
    use md5::{Md5, Digest};
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.as_slice() == expected_md5
}

/// Decrypt an encrypted block (header + encrypted data)
///
/// # Arguments
/// * `reader` - Reader positioned at the start of encrypted block
/// * `key` - 32-byte encryption key
///
/// # Returns
/// Decrypted data with original size
#[allow(dead_code)]
pub fn decrypt_block(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if data.len() < ENCRYPTED_HEADER_SIZE {
        bail!("Encrypted block too short");
    }

    // Parse header
    let header = EncryptedHeader::parse(&data[..ENCRYPTED_HEADER_SIZE])?;
    
    // Calculate encrypted data size (aligned to 16 bytes)
    let encrypted_size = align_to_16(header.original_size) as usize;
    let total_size = ENCRYPTED_HEADER_SIZE + encrypted_size;
    
    if data.len() < total_size {
        bail!(
            "Encrypted block data too short: expected {} bytes, got {}",
            total_size,
            data.len()
        );
    }

    // Extract and decrypt data
    let encrypted_data = &data[ENCRYPTED_HEADER_SIZE..total_size];
    let decrypted = decrypt_cfb(encrypted_data, key, &header.iv);

    // Truncate to original size
    let original_size = header.original_size as usize;
    let result = decrypted[..original_size].to_vec();

    // Verify MD5
    if !verify_md5(&result, &header.md5) {
        bail!("Invalid encryption key (MD5 mismatch)");
    }

    Ok(result)
}

/// Parse a 64-character hex string into a 32-byte key
///
/// # Arguments
/// * `hex` - 64 hexadecimal characters representing 32 bytes
///
/// # Returns
/// 32-byte key array
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_to_16() {
        assert_eq!(align_to_16(0), 0);
        assert_eq!(align_to_16(1), 16);
        assert_eq!(align_to_16(15), 16);
        assert_eq!(align_to_16(16), 16);
        assert_eq!(align_to_16(17), 32);
        assert_eq!(align_to_16(100), 112);
    }

    #[test]
    fn test_parse_hex_key() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = parse_hex_key(hex).unwrap();
        assert_eq!(key[0], 0x01);
        assert_eq!(key[1], 0x23);
        assert_eq!(key[15], 0xef);
        assert_eq!(key[31], 0xef);
    }

    #[test]
    fn test_parse_hex_key_invalid_length() {
        let result = parse_hex_key("0123");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_header_parse() {
        let mut data = [0u8; 40];
        // MD5: all 0x11
        data[0..16].fill(0x11);
        // Original size: 256 (little-endian)
        data[16..24].copy_from_slice(&256i64.to_le_bytes());
        // IV: all 0x22
        data[24..40].fill(0x22);

        let header = EncryptedHeader::parse(&data).unwrap();
        assert_eq!(header.md5, [0x11; 16]);
        assert_eq!(header.original_size, 256);
        assert_eq!(header.iv, [0x22; 16]);
    }
}
