//! PCK encryption key bruteforcer
//!
//! Scans executable files to find embedded 32-byte AES-256 encryption keys
//! by attempting to decrypt encrypted PCK data with each potential key.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::crypto::{align_to_16, decrypt_cfb, verify_md5, EncryptedHeader, ENCRYPTED_HEADER_SIZE};
use crate::{PckFile, PACK_DIR_ENCRYPTED, PCK_FILE_ENCRYPTED};

/// Result of a bruteforce search
#[derive(Debug, Clone, Default)]
pub struct BruteforceResult {
    /// Whether a key was found
    pub found: bool,
    /// The found key as hex string (64 characters)
    pub key_hex: String,
    /// The found key as raw bytes
    pub key_bytes: [u8; 32],
    /// Address in the executable where the key was found
    pub address: u64,
}

/// Progress callback type
pub type ProgressCallback = Box<dyn Fn(BruteforceProgress) + Send + Sync>;

/// Progress information during bruteforce
#[derive(Debug, Clone)]
pub struct BruteforceProgress {
    /// Current address being scanned
    pub current_address: u64,
    /// Total bytes to scan
    pub total_bytes: u64,
    /// Percentage complete (0.0 - 100.0)
    pub percent: f64,
    /// Elapsed time
    pub elapsed: Duration,
    /// Estimated remaining time
    pub remaining: Duration,
    /// Keys tested per second
    pub keys_per_second: u64,
}

/// Configuration for bruteforce operation
#[derive(Debug, Clone)]
pub struct BruteforceConfig {
    /// Number of threads to use (default: number of CPU cores)
    pub threads: usize,
    /// Start address in executable (default: 0)
    pub start_address: u64,
    /// End address in executable (default: file size)
    pub end_address: Option<u64>,
    /// Progress report interval in milliseconds (default: 250)
    pub report_interval_ms: u64,
}

impl Default for BruteforceConfig {
    fn default() -> Self {
        Self {
            threads: num_cpus::get().max(1),
            start_address: 0,
            end_address: None,
            report_interval_ms: 250,
        }
    }
}

/// Bruteforcer for finding encryption keys in executables
pub struct Bruteforcer {
    config: BruteforceConfig,
    cancelled: Arc<AtomicBool>,
}

impl Bruteforcer {
    /// Create a new bruteforcer with default configuration
    pub fn new() -> Self {
        Self {
            config: BruteforceConfig::default(),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a new bruteforcer with custom configuration
    pub fn with_config(config: BruteforceConfig) -> Self {
        Self {
            config,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Cancel the bruteforce operation
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Check if cancelled
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Start bruteforce search
    ///
    /// # Arguments
    /// * `exe_path` - Path to the executable file to scan
    /// * `pck_path` - Path to the encrypted PCK file
    /// * `progress_cb` - Optional progress callback
    pub fn start<P1: AsRef<Path>, P2: AsRef<Path>>(
        &self,
        exe_path: P1,
        pck_path: P2,
        progress_cb: Option<ProgressCallback>,
    ) -> Result<BruteforceResult> {
        let exe_path = exe_path.as_ref();
        let pck_path = pck_path.as_ref();

        // Load PCK to get encryption info (without key, just to read header)
        let pck = PckFile::load(pck_path, None, None)?;

        if !pck.is_encrypted() {
            bail!("PCK file is not encrypted");
        }

        // Find a suitable encrypted file for testing
        let test_data = self.prepare_test_data(&pck, pck_path)?;

        // Get executable file size
        let exe_file = File::open(exe_path).context("Failed to open executable")?;
        let exe_size = exe_file.metadata()?.len();

        let start_addr = self.config.start_address;
        let end_addr = self.config.end_address.unwrap_or(exe_size).min(exe_size);

        if start_addr >= end_addr {
            bail!("Start address must be less than end address");
        }

        // For embedded PCK, limit search to before PCK start
        let end_addr = if pck.is_embedded() {
            end_addr.min(pck.pck_start())
        } else {
            end_addr
        };

        if start_addr >= end_addr {
            bail!("Search range is empty (start >= end after adjusting for embedded PCK)");
        }

        let total_bytes = end_addr - start_addr;
        let threads = self.config.threads.min(total_bytes as usize / 32).max(1);

        // Shared state
        let found = Arc::new(AtomicBool::new(false));
        let progress_counter = Arc::new(AtomicU64::new(0));
        let result: Arc<std::sync::Mutex<BruteforceResult>> =
            Arc::new(std::sync::Mutex::new(BruteforceResult::default()));

        let start_time = Instant::now();

        // Spawn worker threads
        let chunk_size = total_bytes / threads as u64;
        let mut handles = Vec::with_capacity(threads);

        for i in 0..threads {
            let chunk_start = start_addr + (i as u64 * chunk_size);
            let chunk_end = if i == threads - 1 {
                end_addr
            } else {
                chunk_start + chunk_size
            };

            let exe_path = exe_path.to_path_buf();
            let test_data = test_data.clone();
            let found = Arc::clone(&found);
            let cancelled = Arc::clone(&self.cancelled);
            let progress_counter = Arc::clone(&progress_counter);
            let result = Arc::clone(&result);

            let handle = thread::spawn(move || {
                if let Err(e) = bruteforce_range(
                    &exe_path,
                    chunk_start,
                    chunk_end,
                    &test_data,
                    &found,
                    &cancelled,
                    &progress_counter,
                    &result,
                ) {
                    eprintln!("Thread {} error: {}", i, e);
                }
            });

            handles.push(handle);
        }

        // Progress reporting
        if let Some(cb) = progress_cb {
            let found = Arc::clone(&found);
            let cancelled = Arc::clone(&self.cancelled);
            let progress_counter = Arc::clone(&progress_counter);
            let report_interval = Duration::from_millis(self.config.report_interval_ms);

            while !found.load(Ordering::SeqCst) && !cancelled.load(Ordering::SeqCst) {
                thread::sleep(report_interval);

                let current = progress_counter.load(Ordering::SeqCst);
                let elapsed = start_time.elapsed();
                let percent = (current as f64 / total_bytes as f64) * 100.0;

                let keys_per_second = if elapsed.as_secs() > 0 {
                    current / elapsed.as_secs()
                } else {
                    current
                };

                let remaining = if percent > 0.0 {
                    Duration::from_secs_f64(elapsed.as_secs_f64() * (100.0 - percent) / percent)
                } else {
                    Duration::from_secs(0)
                };

                cb(BruteforceProgress {
                    current_address: start_addr + current,
                    total_bytes,
                    percent,
                    elapsed,
                    remaining,
                    keys_per_second,
                });

                // Check if all threads finished
                if handles.iter().all(|h| h.is_finished()) {
                    break;
                }
            }
        }

        // Wait for all threads
        for handle in handles {
            let _ = handle.join();
        }

        let final_result = result.lock().unwrap().clone();
        Ok(final_result)
    }

    /// Prepare test data for key validation
    fn prepare_test_data(&self, pck: &PckFile, pck_path: &Path) -> Result<TestData> {
        let mut file = File::open(pck_path)?;

        // If index is encrypted, use index data for testing
        if pck.header().flags & PACK_DIR_ENCRYPTED != 0 {
            // Read encrypted index header
            file.seek(SeekFrom::Start(pck.header().file_offset_base))?;
            let mut header_buf = [0u8; ENCRYPTED_HEADER_SIZE];
            file.read_exact(&mut header_buf)?;

            let header = EncryptedHeader::parse(&header_buf)?;
            let encrypted_size = align_to_16(header.original_size) as usize;

            // Read encrypted data
            let mut encrypted_data = vec![0u8; encrypted_size];
            file.read_exact(&mut encrypted_data)?;

            return Ok(TestData {
                header,
                encrypted_data,
            });
        }

        // Otherwise, find a suitable encrypted file
        let encrypted_files: Vec<_> = pck
            .entries()
            .filter(|entry| entry.flags & PCK_FILE_ENCRYPTED != 0)
            .collect();

        if encrypted_files.is_empty() {
            bail!("No encrypted files found in PCK");
        }

        // Prefer files between 5KB and 1MB for faster validation
        let test_file = encrypted_files
            .iter()
            .filter(|e| e.size >= 5 * 1024 && e.size < 1024 * 1024)
            .min_by_key(|e| e.size)
            .or_else(|| {
                encrypted_files
                    .iter()
                    .filter(|e| e.size > 512 && e.size < 5 * 1024)
                    .max_by_key(|e| e.size)
            })
            .or_else(|| encrypted_files.iter().min_by_key(|e| e.size))
            .copied()
            .ok_or_else(|| anyhow::anyhow!("No suitable test file found"))?;

        // Read encrypted file header and data
        file.seek(SeekFrom::Start(test_file.offset))?;
        let mut header_buf = [0u8; ENCRYPTED_HEADER_SIZE];
        file.read_exact(&mut header_buf)?;

        let header = EncryptedHeader::parse(&header_buf)?;
        let encrypted_size = align_to_16(header.original_size) as usize;

        let mut encrypted_data = vec![0u8; encrypted_size];
        file.read_exact(&mut encrypted_data)?;

        Ok(TestData {
            header,
            encrypted_data,
        })
    }
}

impl Default for Bruteforcer {
    fn default() -> Self {
        Self::new()
    }
}

/// Test data for key validation
#[derive(Clone)]
struct TestData {
    header: EncryptedHeader,
    encrypted_data: Vec<u8>,
}

impl TestData {
    /// Try to decrypt with the given key and verify MD5
    fn try_key(&self, key: &[u8; 32]) -> bool {
        let decrypted = decrypt_cfb(&self.encrypted_data, key, &self.header.iv);
        let original_size = self.header.original_size as usize;

        if decrypted.len() < original_size {
            return false;
        }

        verify_md5(&decrypted[..original_size], &self.header.md5)
    }
}

/// Bruteforce a range of addresses in the executable
#[allow(clippy::too_many_arguments)]
fn bruteforce_range(
    exe_path: &Path,
    start: u64,
    end: u64,
    test_data: &TestData,
    found: &AtomicBool,
    cancelled: &AtomicBool,
    progress: &AtomicU64,
    result: &std::sync::Mutex<BruteforceResult>,
) -> Result<()> {
    let mut file = File::open(exe_path)?;
    file.seek(SeekFrom::Start(start))?;

    let mut buffer = vec![0u8; 32 + 4096]; // Read in chunks for efficiency
    let mut pos = start;

    while pos < end && !found.load(Ordering::Relaxed) && !cancelled.load(Ordering::Relaxed) {
        let to_read = ((end - pos) as usize + 32).min(buffer.len());
        let bytes_read = file.read(&mut buffer[..to_read])?;

        if bytes_read < 32 {
            break;
        }

        // Slide through the buffer
        for i in 0..(bytes_read - 31) {
            if found.load(Ordering::Relaxed) || cancelled.load(Ordering::Relaxed) {
                break;
            }

            let key: [u8; 32] = buffer[i..i + 32].try_into().unwrap();

            if test_data.try_key(&key) {
                found.store(true, Ordering::SeqCst);

                let mut res = result.lock().unwrap();
                res.found = true;
                res.key_bytes = key;
                res.key_hex = bytes_to_hex(&key);
                res.address = pos + i as u64;

                return Ok(());
            }
        }

        // Move position, overlapping by 31 bytes to not miss keys at chunk boundaries
        let advance = (bytes_read - 31).max(1);
        pos += advance as u64;
        progress.fetch_add(advance as u64, Ordering::Relaxed);

        // Seek back if we need to continue
        if pos < end {
            file.seek(SeekFrom::Start(pos))?;
        }
    }

    // Update final progress
    progress.fetch_add((end - pos).min(31), Ordering::Relaxed);

    Ok(())
}

/// Convert bytes to hex string
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_hex() {
        let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(bytes_to_hex(&bytes), "0123456789abcdef");
    }

    #[test]
    fn test_bruteforce_config_default() {
        let config = BruteforceConfig::default();
        assert!(config.threads >= 1);
        assert_eq!(config.start_address, 0);
        assert!(config.end_address.is_none());
    }
}
