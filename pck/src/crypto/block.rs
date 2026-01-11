use aes::cipher::AsyncStreamCipher;
use aes::Aes256;
use anyhow::{bail, Result};
use cfb_mode::cipher::KeyIvInit;
use cfb_mode::{Decryptor, Encryptor};
use md5::{Digest, Md5};
use rand::RngCore;

type Aes256CfbDec = Decryptor<Aes256>;
type Aes256CfbEnc = Encryptor<Aes256>;

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
pub fn decrypt_cfb(data: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    let decryptor = Aes256CfbDec::new(key.into(), iv.into());
    let mut buffer = data.to_vec();
    decryptor.decrypt(&mut buffer);
    buffer
}

/// Encrypt data using AES-256-CFB mode
pub fn encrypt_cfb(data: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    let encryptor = Aes256CfbEnc::new(key.into(), iv.into());
    let aligned_size = align_to_16(data.len() as u64) as usize;
    let mut buffer = vec![0u8; aligned_size];
    buffer[..data.len()].copy_from_slice(data);
    encryptor.encrypt(&mut buffer);
    buffer
}

/// Generate a random 16-byte IV for encryption
pub fn generate_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    rand::rng().fill_bytes(&mut iv);
    iv
}

/// Compute MD5 hash of data
pub fn compute_md5(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut md5 = [0u8; 16];
    md5.copy_from_slice(&result[..]);
    md5
}

/// Encrypt a block of data and write the encrypted block (header + ciphertext)
pub fn encrypt_block(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let md5 = compute_md5(data);
    let iv = generate_iv();
    let encrypted = encrypt_cfb(data, key, &iv);

    let mut result = Vec::with_capacity(ENCRYPTED_HEADER_SIZE + encrypted.len());
    result.extend_from_slice(&md5);
    result.extend_from_slice(&(data.len() as i64).to_le_bytes());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&encrypted);

    result
}

/// Align size to 16-byte boundary (AES block size)
#[inline]
pub fn align_to_16(size: u64) -> u64 {
    (size + 15) & !15
}

/// Verify MD5 hash of decrypted data
pub fn verify_md5(data: &[u8], expected_md5: &[u8; 16]) -> bool {
    let mut hasher = Md5::new();
    hasher.update(data);
    let result = hasher.finalize();
    result.as_slice() == expected_md5
}

/// Decrypt an encrypted block (header + encrypted data)
#[allow(dead_code)]
pub fn decrypt_block(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if data.len() < ENCRYPTED_HEADER_SIZE {
        bail!("Encrypted block too short");
    }

    let header = EncryptedHeader::parse(&data[..ENCRYPTED_HEADER_SIZE])?;

    let encrypted_size = align_to_16(header.original_size) as usize;
    let total_size = ENCRYPTED_HEADER_SIZE + encrypted_size;

    if data.len() < total_size {
        bail!(
            "Encrypted block data too short: expected {} bytes, got {}",
            total_size,
            data.len()
        );
    }

    let encrypted_data = &data[ENCRYPTED_HEADER_SIZE..total_size];
    let decrypted = decrypt_cfb(encrypted_data, key, &header.iv);

    let original_size = header.original_size as usize;
    let result = decrypted[..original_size].to_vec();

    if !verify_md5(&result, &header.md5) {
        bail!("Invalid encryption key (MD5 mismatch)");
    }

    Ok(result)
}
