use aes::cipher::{BlockDecryptMut, BlockSizeUser};
use aes::Aes256;
use anyhow::{bail, Result};
use cfb_mode::cipher::KeyIvInit;
use cfb_mode::Decryptor;
use md5::{Digest, Md5};
use std::io::{Read, Write};

use super::block::align_to_16;

type Aes256CfbDec = Decryptor<Aes256>;

/// Default chunk size for streaming decryption (64 KB)
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Streaming decryptor for large encrypted files.
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
    pub fn decrypt_chunk<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
        chunk_size: usize,
    ) -> Result<usize> {
        if self.bytes_written >= self.original_size {
            return Ok(0);
        }

        let remaining_encrypted = self.encrypted_size - self.bytes_read;
        let block_size = <Aes256CfbDec as BlockSizeUser>::block_size();
        let aligned_chunk = (chunk_size / block_size).max(1) * block_size;
        let to_read = aligned_chunk.min(remaining_encrypted as usize);

        if to_read == 0 {
            return Ok(0);
        }

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

        let full_blocks = total_read / block_size;
        if full_blocks > 0 {
            let full_block_bytes = full_blocks * block_size;
            for chunk in buffer[..full_block_bytes].chunks_mut(block_size) {
                self.decryptor.decrypt_block_mut(chunk.into());
            }
        }

        let remaining = total_read % block_size;
        if remaining > 0 {
            let start = full_blocks * block_size;
            let mut last_block = [0u8; 16];
            last_block[..remaining].copy_from_slice(&buffer[start..]);
            self.decryptor.decrypt_block_mut((&mut last_block).into());
            buffer[start..].copy_from_slice(&last_block[..remaining]);
        }

        let remaining_original = self.original_size - self.bytes_written;
        let to_write = (total_read as u64).min(remaining_original) as usize;

        let output = &buffer[..to_write];
        self.md5_hasher.update(output);
        writer.write_all(output)?;
        self.bytes_written += to_write as u64;

        Ok(to_write)
    }

    /// Decrypt all remaining data from reader to writer.
    pub fn decrypt_all<R: Read, W: Write>(&mut self, reader: &mut R, writer: &mut W) -> Result<u64> {
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
    pub fn verify_md5(self, expected_md5: &[u8; 16]) -> Result<()> {
        let result = self.md5_hasher.finalize();
        if result.as_slice() == expected_md5 {
            Ok(())
        } else {
            bail!("Invalid encryption key (MD5 mismatch)")
        }
    }

    #[allow(dead_code)]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    #[allow(dead_code)]
    pub fn is_complete(&self) -> bool {
        self.bytes_written >= self.original_size
    }
}
