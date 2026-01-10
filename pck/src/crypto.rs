//! AES-256-CFB encryption/decryption support for Godot 4 encrypted PCK files.
//!
//! Godot 4 uses AES-256-CFB mode for encrypting PCK files.
//! Each encrypted block has a 40-byte header: MD5(16) + original_size(8) + IV(16)

use aes::cipher::{AsyncStreamCipher, BlockDecryptMut, BlockSizeUser};
use aes::Aes256;
use anyhow::{bail, Result};
use cfb_mode::cipher::KeyIvInit;
use cfb_mode::Decryptor;
use md5::{Digest, Md5};
use std::io::{Read, Write};

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
    use md5::{Digest, Md5};
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

/// Default chunk size for streaming decryption (64 KB)
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Streaming decryptor for large encrypted files.
///
/// This allows decrypting files in chunks without loading the entire
/// encrypted content into memory. It also computes MD5 incrementally.
///
/// # Example
/// ```ignore
/// let mut decryptor = StreamingDecryptor::new(&key, &header.iv, header.original_size);
/// while let Some(chunk) = decryptor.decrypt_chunk(&mut reader, &mut writer)? {
///     // chunk written to writer
/// }
/// decryptor.verify_md5(&header.md5)?;
/// ```
pub struct StreamingDecryptor {
    decryptor: Aes256CfbDec,
    md5_hasher: Md5,
    original_size: u64,
    bytes_written: u64,
    encrypted_size: u64,
    bytes_read: u64,
}

impl StreamingDecryptor {
    /// Create a new streaming decryptor.
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `iv` - 16-byte initialization vector
    /// * `original_size` - Original (unencrypted) data size
    pub fn new(key: &[u8; 32], iv: &[u8; 16], original_size: u64) -> Self {
        Self {
            decryptor: Aes256CfbDec::new(key.into(), iv.into()),
            md5_hasher: Md5::new(),
            original_size,
            bytes_written: 0,
            encrypted_size: align_to_16(original_size),
            bytes_read: 0,
        }
    }

    /// Decrypt a chunk of data from reader and write to writer.
    ///
    /// Returns the number of bytes written, or 0 if decryption is complete.
    ///
    /// # Arguments
    /// * `reader` - Source of encrypted data
    /// * `writer` - Destination for decrypted data
    /// * `chunk_size` - Maximum bytes to process in this call (should be multiple of 16)
    pub fn decrypt_chunk<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        chunk_size: usize,
    ) -> Result<usize> {
        if self.bytes_written >= self.original_size {
            return Ok(0);
        }

        // Calculate how much encrypted data to read (align to block size for efficiency)
        let remaining_encrypted = self.encrypted_size - self.bytes_read;
        let block_size = <Aes256CfbDec as BlockSizeUser>::block_size();
        // Round chunk_size down to block boundary, but at least one block
        let aligned_chunk = (chunk_size / block_size).max(1) * block_size;
        let to_read = aligned_chunk.min(remaining_encrypted as usize);

        if to_read == 0 {
            return Ok(0);
        }

        // Read encrypted chunk
        let mut buffer = vec![0u8; to_read];
        let mut total_read = 0;
        while total_read < to_read {
            let n = reader.read(&mut buffer[total_read..])?;
            if n == 0 {
                break;
            }
            total_read += n;
        }

        if total_read == 0 {
            return Ok(0);
        }
        buffer.truncate(total_read);
        self.bytes_read += total_read as u64;

        // Decrypt in place using BlockDecryptMut
        // Process full blocks
        let full_blocks = total_read / block_size;
        if full_blocks > 0 {
            let full_block_bytes = full_blocks * block_size;
            for chunk in buffer[..full_block_bytes].chunks_mut(block_size) {
                self.decryptor.decrypt_block_mut(chunk.into());
            }
        }

        // Handle remaining bytes (partial block at the end)
        let remaining = total_read % block_size;
        if remaining > 0 {
            let start = full_blocks * block_size;
            // For partial blocks, we need to decrypt a full block and take what we need
            let mut last_block = [0u8; 16]; // AES block size
            last_block[..remaining].copy_from_slice(&buffer[start..]);
            self.decryptor.decrypt_block_mut((&mut last_block).into());
            buffer[start..].copy_from_slice(&last_block[..remaining]);
        }

        // Calculate how much of the decrypted data is actual content (not padding)
        let remaining_original = self.original_size - self.bytes_written;
        let to_write = (total_read as u64).min(remaining_original) as usize;

        // Update MD5 and write
        let output = &buffer[..to_write];
        self.md5_hasher.update(output);
        writer.write_all(output)?;
        self.bytes_written += to_write as u64;

        Ok(to_write)
    }

    /// Decrypt all remaining data from reader to writer.
    ///
    /// # Arguments
    /// * `reader` - Source of encrypted data
    /// * `writer` - Destination for decrypted data
    pub fn decrypt_all<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<u64> {
        let mut total = 0u64;
        loop {
            let written = self.decrypt_chunk(reader, writer, DEFAULT_CHUNK_SIZE)?;
            if written == 0 {
                break;
            }
            total += written as u64;
        }
        Ok(total)
    }

    /// Verify the MD5 hash of the decrypted data.
    ///
    /// This should be called after all data has been decrypted.
    ///
    /// # Arguments
    /// * `expected_md5` - Expected MD5 hash from encrypted header
    pub fn verify_md5(self, expected_md5: &[u8; 16]) -> Result<()> {
        let result = self.md5_hasher.finalize();
        if result.as_slice() == expected_md5 {
            Ok(())
        } else {
            bail!("Invalid encryption key (MD5 mismatch)")
        }
    }

    /// Get the number of bytes written so far.
    #[allow(dead_code)]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Check if decryption is complete.
    #[allow(dead_code)]
    pub fn is_complete(&self) -> bool {
        self.bytes_written >= self.original_size
    }
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
