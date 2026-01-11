use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use regex::Regex;

mod crypto;
pub use crypto::{
    align_to_16, compute_md5, decrypt_cfb, encrypt_block, encrypt_cfb, generate_iv, parse_hex_key,
    verify_md5, EncryptedHeader, ENCRYPTED_HEADER_SIZE,
};
mod bruteforce;
pub use bruteforce::{
    BruteforceConfig, BruteforceProgress, BruteforceResult, Bruteforcer, ProgressCallback,
};
mod embedded;
pub use embedded::{
    change_version, merge_pck, patch_pck, remove_pck, rip_pck, split_pck, ChangeVersionResult,
    MergeResult, PatchResult, RemoveResult, RipResult, SplitResult,
};

pub const PCK_HEADER_MAGIC: u32 = 0x4350_4447;

pub const PACK_DIR_ENCRYPTED: u32 = 1 << 0;
pub const PCK_FILE_ENCRYPTED: u32 = 1 << 0;
pub const PCK_FILE_DELETED: u32 = 1 << 1;

pub const PCK_FILE_RELATIVE_BASE: u32 = 1 << 1;
pub const PCK_FILE_SPARSE_BUNDLE: u32 = 1 << 2;

pub const MAX_SUPPORTED_PCK_VERSION_LOAD: u32 = 3;
pub const GODOT_PCK_EXTENSION: &str = ".pck";
pub const GODOT_RES_PATH: &str = "res://";
pub const GODOT_USER_PATH: &str = "user://";
/// When extracting, `user://` paths are mapped into this folder to stay filesystem-friendly.
pub const GODOT_EXTRACT_USER_DIR: &str = "@@user@@";
/// Suffix used to represent a "Removal" file when extracting/packing.
pub const GODOT_REMOVAL_TAG: &str = ".@@removal@@";

mod write;
pub use write::{
    prepare_pck_path, prepare_pck_path_versioned, BuildEntry, EncryptionSettings, EntrySource,
    PckBuilder,
};

#[derive(Debug, Clone)]
pub struct FileFilter {
    min_size_limit: u64,
    max_size_limit: u64,
    include_patterns: Vec<Regex>,
    exclude_patterns: Vec<Regex>,
    override_patterns: Vec<Regex>,
}

impl FileFilter {
    pub fn from_cli(
        min_size: Option<u64>,
        max_size: Option<u64>,
        include_regex: &[String],
        exclude_regex: &[String],
        override_regex: &[String],
    ) -> Result<Self> {
        let include_patterns = include_regex
            .iter()
            .map(|text| Regex::new(text))
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("compile include regex")?;

        let exclude_patterns = exclude_regex
            .iter()
            .map(|text| Regex::new(text))
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("compile exclude regex")?;

        let override_patterns = override_regex
            .iter()
            .map(|text| Regex::new(text))
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("compile override regex")?;

        Ok(Self {
            min_size_limit: min_size.unwrap_or(0),
            max_size_limit: max_size.unwrap_or(u64::MAX),
            include_patterns,
            exclude_patterns,
            override_patterns,
        })
    }

    pub fn include(&self, path: &str, size: u64) -> bool {
        if !self.override_patterns.is_empty() {
            for pattern in &self.override_patterns {
                if pattern.is_match(path) {
                    return true;
                }
            }
        }

        if !self.include_patterns.is_empty() {
            let mut matched = false;
            for pattern in &self.include_patterns {
                if pattern.is_match(path) {
                    matched = true;
                    break;
                }
            }

            if !matched {
                return false;
            }
        }

        if size < self.min_size_limit {
            return false;
        }

        if size > self.max_size_limit {
            return false;
        }

        if !self.exclude_patterns.is_empty() {
            for pattern in &self.exclude_patterns {
                if pattern.is_match(path) {
                    return false;
                }
            }
        }

        true
    }
}

#[derive(Debug, Clone, Copy)]
pub struct GodotVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl fmt::Display for GodotVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Clone)]
pub struct PckHeader {
    pub format_version: u32,
    pub godot_version: GodotVersion,
    pub flags: u32,
    pub file_offset_base: u64,
    pub directory_offset: Option<u64>,
}

impl PckHeader {
    pub fn godot_version_string(&self) -> String {
        self.godot_version.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct PckEntry {
    pub path: String,
    pub offset: u64,
    pub size: u64,
    pub md5: [u8; 16],
    pub flags: u32,
}

#[derive(Debug, Clone)]
pub struct PckFile {
    path: PathBuf,
    header: PckHeader,
    entries: BTreeMap<String, PckEntry>,
    excluded_by_filter: usize,
    /// Encryption key for encrypted PCK files (32 bytes)
    encryption_key: Option<[u8; 32]>,
    /// Whether this PCK is embedded in an executable
    embedded: bool,
    /// Start offset of the PCK data within the file (0 for standalone PCK)
    pck_start: u64,
    /// End offset of the PCK data within the file
    pck_end: u64,
}

impl PckFile {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check if this PCK file is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.header.flags & PACK_DIR_ENCRYPTED != 0
    }

    /// Check if this PCK is embedded in an executable
    pub fn is_embedded(&self) -> bool {
        self.embedded
    }

    /// Get the start offset of the PCK data within the file
    pub fn pck_start(&self) -> u64 {
        self.pck_start
    }

    /// Get the end offset of the PCK data within the file
    pub fn pck_end(&self) -> u64 {
        self.pck_end
    }

    /// Load a PCK file with optional encryption key
    ///
    /// # Arguments
    /// * `path` - Path to the PCK file
    /// * `filter` - Optional file filter
    /// * `encryption_key` - Optional 32-byte encryption key for encrypted PCK files
    pub fn load(
        path: impl AsRef<Path>,
        filter: Option<&FileFilter>,
        encryption_key: Option<[u8; 32]>,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        let mut file = File::open(&path)
            .with_context(|| format!("opening pck file for reading: {}", path.display()))?;

        // Detect embedded PCK or standalone PCK
        let (pck_start, pck_end, embedded) = detect_embedded_pck(&mut file)?;

        // Seek to PCK start and read magic
        file.seek(SeekFrom::Start(pck_start))
            .context("seeking to pck start")?;

        let magic = read_u32_le(&mut file).context("reading magic")?;
        if magic != PCK_HEADER_MAGIC {
            bail!("invalid magic number");
        }

        let format_version = read_u32_le(&mut file).context("reading pck format version")?;

        let major = read_u32_le(&mut file).context("reading godot major")?;
        let minor = read_u32_le(&mut file).context("reading godot minor")?;
        let patch = read_u32_le(&mut file).context("reading godot patch")?;

        if format_version > MAX_SUPPORTED_PCK_VERSION_LOAD {
            bail!("pck is unsupported version: {format_version}");
        }

        let mut flags = 0u32;
        let mut file_offset_base = 0u64;
        let mut directory_offset = None;

        if format_version >= 2 {
            flags = read_u32_le(&mut file).context("reading pck flags")?;
            file_offset_base = read_u64_le(&mut file).context("reading file offset base")?;
        }

        if flags & PACK_DIR_ENCRYPTED != 0 && encryption_key.is_none() {
            bail!("PCK is encrypted, please provide --encryption-key");
        }

        if flags & PCK_FILE_SPARSE_BUNDLE != 0 {
            // This matches the old tool: it warns but continues.
            println!("Warning: Sparse pck detected, this is unlikely to work!");
        }

        if format_version >= 3 || (format_version == 2 && (flags & PCK_FILE_RELATIVE_BASE != 0)) {
            file_offset_base = file_offset_base
                .checked_add(pck_start)
                .context("file offset base overflow")?;
        }

        if format_version >= 3 {
            let dir_off = read_u64_le(&mut file).context("reading directory offset")?;
            directory_offset = Some(dir_off);
            file.seek(SeekFrom::Start(
                pck_start
                    .checked_add(dir_off)
                    .context("directory offset overflow")?,
            ))
            .context("seeking to directory")?;
        } else {
            for _ in 0..16 {
                let _ = read_u32_le(&mut file).context("reading reserved header")?;
            }
        }

        // Handle encrypted directory/index
        let mut index_cursor: Option<std::io::Cursor<Vec<u8>>> = None;

        if flags & PACK_DIR_ENCRYPTED != 0 {
            let key = encryption_key.as_ref().unwrap();

            // Read encrypted header (40 bytes)
            let mut header_buf = [0u8; crypto::ENCRYPTED_HEADER_SIZE];
            file.read_exact(&mut header_buf)
                .context("reading encrypted index header")?;

            let enc_header = crypto::EncryptedHeader::parse(&header_buf)
                .context("parsing encrypted index header")?;

            // Read encrypted data (aligned to 16 bytes)
            let encrypted_size = crypto::align_to_16(enc_header.original_size) as usize;
            let mut encrypted_data = vec![0u8; encrypted_size];
            file.read_exact(&mut encrypted_data)
                .context("reading encrypted index data")?;

            // Decrypt
            let decrypted = crypto::decrypt_cfb(&encrypted_data, key, &enc_header.iv);

            // Truncate to original size and verify MD5
            let original_size = usize::try_from(enc_header.original_size)
                .context("encrypted index original size too large")?;
            if original_size > decrypted.len() {
                bail!(
                    "Encrypted index original size is larger than decrypted buffer: {} > {}",
                    original_size,
                    decrypted.len()
                );
            }
            let decrypted_trimmed = decrypted[..original_size].to_vec();

            if !crypto::verify_md5(&decrypted_trimmed, &enc_header.md5) {
                bail!("Invalid encryption key (MD5 mismatch on index)");
            }

            index_cursor = Some(std::io::Cursor::new(decrypted_trimmed));
        }

        // Read file count from either decrypted index or file
        let file_count = if let Some(ref mut cursor) = index_cursor {
            read_u32_le(cursor).context("reading file count from decrypted index")?
        } else {
            read_u32_le(&mut file).context("reading file count")?
        };

        let mut excluded_by_filter = 0usize;
        let mut entries = BTreeMap::new();

        for _ in 0..file_count {
            // Read from decrypted index or file
            let (_path_length, path_bytes, rel_offset, size, md5, entry_flags) =
                if let Some(ref mut cursor) = index_cursor {
                    let path_length = read_u32_le(cursor).context("reading path length")? as usize;
                    let mut path_bytes = vec![0u8; path_length];
                    cursor
                        .read_exact(&mut path_bytes)
                        .context("reading path bytes")?;

                    let rel_offset = read_u64_le(cursor).context("reading entry offset")?;
                    let size = read_u64_le(cursor).context("reading entry size")?;

                    let mut md5 = [0u8; 16];
                    cursor.read_exact(&mut md5).context("reading entry md5")?;

                    let mut entry_flags = 0u32;
                    if format_version >= 2 {
                        entry_flags = read_u32_le(cursor).context("reading entry flags")?;
                    }

                    (path_length, path_bytes, rel_offset, size, md5, entry_flags)
                } else {
                    let path_length =
                        read_u32_le(&mut file).context("reading path length")? as usize;
                    let mut path_bytes = vec![0u8; path_length];
                    file.read_exact(&mut path_bytes)
                        .context("reading path bytes")?;

                    let rel_offset = read_u64_le(&mut file).context("reading entry offset")?;
                    let size = read_u64_le(&mut file).context("reading entry size")?;

                    let mut md5 = [0u8; 16];
                    file.read_exact(&mut md5).context("reading entry md5")?;

                    let mut entry_flags = 0u32;
                    if format_version >= 2 {
                        entry_flags = read_u32_le(&mut file).context("reading entry flags")?;
                    }

                    (path_length, path_bytes, rel_offset, size, md5, entry_flags)
                };

            let mut path_bytes = path_bytes;
            while path_bytes.last() == Some(&0) {
                path_bytes.pop();
            }

            let path_string = String::from_utf8_lossy(&path_bytes).to_string();

            let offset = file_offset_base
                .checked_add(rel_offset)
                .context("entry offset overflow")?;

            if let Some(filter) = filter {
                if !filter.include(&path_string, size) {
                    excluded_by_filter += 1;
                    continue;
                }
            }

            entries.insert(
                path_string.clone(),
                PckEntry {
                    path: path_string,
                    offset,
                    size,
                    md5,
                    flags: entry_flags,
                },
            );
        }

        Ok(Self {
            path,
            header: PckHeader {
                format_version,
                godot_version: GodotVersion {
                    major,
                    minor,
                    patch,
                },
                flags,
                file_offset_base,
                directory_offset,
            },
            entries,
            excluded_by_filter,
            encryption_key,
            embedded,
            pck_start,
            pck_end,
        })
    }

    pub fn header(&self) -> &PckHeader {
        &self.header
    }

    pub fn entries(&self) -> impl Iterator<Item = &PckEntry> {
        self.entries.values()
    }

    pub fn excluded_by_filter(&self) -> usize {
        self.excluded_by_filter
    }

    pub fn print_file_list(&self, print_hashes: bool) {
        for entry in self.entries() {
            // Print info for special flags
            if entry.flags & PCK_FILE_ENCRYPTED != 0 {
                if self.encryption_key.is_some() {
                    // We have the key, file will be decrypted during extraction
                } else {
                    println!(
                        "WARNING: pck file ({}) is marked as encrypted, no encryption key provided",
                        entry.path
                    );
                }
            }
            if entry.flags & PCK_FILE_DELETED != 0 {
                println!(
                    "Pck file is marked as removed (but still processing it): {}",
                    entry.path
                );
            }

            print!("{}", entry.path);
            print!(" size: {}", entry.size);

            if entry.flags & PCK_FILE_ENCRYPTED != 0 {
                print!(" [encrypted]");
            }

            if print_hashes {
                print!(" md5: {}", format_md5(entry.md5));
            }

            println!();
        }
    }

    pub fn extract(&self, output_prefix: impl AsRef<Path>, print_extracted: bool) -> Result<()> {
        self.extract_with_options(output_prefix, print_extracted, &ExtractOptions::default())
    }

    pub fn extract_with_options(
        &self,
        output_prefix: impl AsRef<Path>,
        print_extracted: bool,
        options: &ExtractOptions,
    ) -> Result<()> {
        let output_base = output_prefix.as_ref();

        let mut reader = File::open(&self.path)
            .with_context(|| format!("opening pck file for extracting: {}", self.path.display()))?;

        for entry in self.entries() {
            // Handle encrypted files without key
            if entry.flags & PCK_FILE_ENCRYPTED != 0 && self.encryption_key.is_none() {
                match options.no_key_mode {
                    NoKeyMode::Skip => {
                        println!(
                            "WARNING: pck file ({}) is marked as encrypted, skipping (no encryption key)",
                            entry.path
                        );
                        continue;
                    }
                    NoKeyMode::Cancel => {
                        bail!(
                            "Encrypted file encountered without key: {}. Use --no-key-mode skip to skip encrypted files.",
                            entry.path
                        );
                    }
                }
            }
            if entry.flags & PCK_FILE_DELETED != 0 {
                println!(
                    "Pck file is marked as removed (but still processing it): {}",
                    entry.path
                );
            }

            let mut relative_path = entry_path_to_relative(&entry.path);
            if entry.flags & PCK_FILE_DELETED != 0 {
                let mut name = relative_path.to_string_lossy().to_string();
                name.push_str(GODOT_REMOVAL_TAG);
                relative_path = PathBuf::from(name);
            }
            let target_file = output_base.join(&relative_path);

            // Check if file exists and handle overwrite option
            if target_file.exists() && !options.overwrite {
                if print_extracted {
                    println!("Skipping (exists): {}", target_file.display());
                }
                continue;
            }

            if print_extracted {
                let encrypted_note = if entry.flags & PCK_FILE_ENCRYPTED != 0 {
                    " [decrypting]"
                } else {
                    ""
                };
                let overwrite_note = if target_file.exists() {
                    " [overwrite]"
                } else {
                    ""
                };
                println!(
                    "Extracting{}{} {} to {}",
                    encrypted_note,
                    overwrite_note,
                    entry.path,
                    target_file.display()
                );
            }

            if let Some(parent) = target_file.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("creating target directory ({})", parent.display())
                    })?;
                }
            }

            let mut writer = File::create(&target_file)
                .with_context(|| format!("opening file for writing: {}", target_file.display()))?;

            // Handle encrypted files
            if entry.flags & PCK_FILE_ENCRYPTED != 0 {
                let key = self.encryption_key.as_ref().unwrap();

                // Seek to entry offset
                reader
                    .seek(SeekFrom::Start(entry.offset))
                    .with_context(|| format!("seeking to entry offset for {}", entry.path))?;

                // Read encrypted header (40 bytes)
                let mut header_buf = [0u8; crypto::ENCRYPTED_HEADER_SIZE];
                reader
                    .read_exact(&mut header_buf)
                    .with_context(|| format!("reading encrypted header for {}", entry.path))?;

                let enc_header = crypto::EncryptedHeader::parse(&header_buf)
                    .with_context(|| format!("parsing encrypted header for {}", entry.path))?;

                // Validate size consistency
                let original_size = enc_header.original_size;
                if original_size != entry.size {
                    bail!(
                        "Encrypted file size mismatch for {} (index size: {}, block header size: {})",
                        entry.path,
                        entry.size,
                        original_size
                    );
                }

                // Use streaming decryption to avoid loading entire file into memory
                let mut decryptor =
                    crypto::StreamingDecryptor::new(key, &enc_header.iv, original_size);
                decryptor
                    .decrypt_all(&mut reader, &mut writer)
                    .with_context(|| format!("streaming decrypt for {}", entry.path))?;

                // Verify MD5
                decryptor
                    .verify_md5(&enc_header.md5)
                    .with_context(|| format!("MD5 verification failed for {}", entry.path))?;
            } else {
                // Non-encrypted file: copy directly
                reader
                    .seek(SeekFrom::Start(entry.offset))
                    .with_context(|| format!("seeking to entry offset for {}", entry.path))?;

                if options.check_md5 {
                    // Read into buffer to compute MD5 while writing
                    let mut buffer = vec![0u8; entry.size as usize];
                    reader
                        .read_exact(&mut buffer)
                        .with_context(|| format!("reading entry data for {}", entry.path))?;

                    // Compute MD5 and verify
                    let computed_md5 = compute_md5(&buffer);
                    if computed_md5 != entry.md5 {
                        bail!(
                            "MD5 mismatch for {}: expected {}, got {}",
                            entry.path,
                            format_md5(entry.md5),
                            format_md5(computed_md5)
                        );
                    }

                    // Write the verified data
                    writer
                        .write_all(&buffer)
                        .with_context(|| format!("writing entry data for {}", entry.path))?;
                } else {
                    // Fast path: copy without MD5 verification
                    let mut take = std::io::Read::by_ref(&mut reader).take(entry.size);
                    let copied = std::io::copy(&mut take, &mut writer)
                        .with_context(|| format!("writing entry data for {}", entry.path))?;

                    if copied != entry.size {
                        bail!("reading file entry content failed (specified offset or data length is too large, pck may be corrupt or malformed)");
                    }
                }
            }

            writer.flush().context("flush writer")?;
        }

        Ok(())
    }
}

/// Options for extraction
#[derive(Debug, Clone, Default)]
pub struct ExtractOptions {
    /// Whether to overwrite existing files (default: false, skip existing)
    pub overwrite: bool,
    /// Whether to verify MD5 checksums after extraction (default: false)
    pub check_md5: bool,
    /// What to do when encountering encrypted files without a key
    /// "skip" = skip the file, "cancel" = abort extraction
    pub no_key_mode: NoKeyMode,
}

/// Mode for handling encrypted files when no key is provided
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub enum NoKeyMode {
    /// Skip encrypted files and continue (default)
    #[default]
    Skip,
    /// Cancel extraction when encountering encrypted files
    Cancel,
}

fn format_md5(bytes: [u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

fn entry_path_to_relative(entry_path: &str) -> PathBuf {
    if let Some(rest) = entry_path.strip_prefix(GODOT_RES_PATH) {
        return PathBuf::from(rest.trim_start_matches('/'));
    }

    if let Some(rest) = entry_path.strip_prefix(GODOT_USER_PATH) {
        let rest = rest.trim_start_matches('/');
        return PathBuf::from(format!("{GODOT_EXTRACT_USER_DIR}/{rest}"));
    }

    PathBuf::from(entry_path.trim_start_matches('/'))
}

fn read_u32_le<R: Read>(reader: &mut R) -> std::io::Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64_le<R: Read>(reader: &mut R) -> std::io::Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Detect if a file contains an embedded PCK (e.g., self-contained executable).
///
/// Returns (pck_start, pck_end, is_embedded):
/// - For standalone PCK: (0, file_length, false)
/// - For embedded PCK: (pck_start_offset, pck_end_offset, true)
///
/// The detection algorithm:
/// 1. Try reading magic at file start
/// 2. If not found, check file end for magic (embedded PCK marker)
/// 3. If found at end, read the PCK size and locate the actual PCK start
fn detect_embedded_pck<R: Read + Seek>(reader: &mut R) -> Result<(u64, u64, bool)> {
    // Get file length
    let file_length = reader.seek(SeekFrom::End(0)).context("seeking to end")?;

    // Try reading magic at the start
    reader
        .seek(SeekFrom::Start(0))
        .context("seeking to start")?;
    let magic = read_u32_le(reader).context("reading magic at start")?;

    if magic == PCK_HEADER_MAGIC {
        // Standalone PCK file
        reader
            .seek(SeekFrom::Start(0))
            .context("seeking back to start")?;
        return Ok((0, file_length, false));
    }

    // Not a standalone PCK, check for embedded PCK at file end
    // Embedded PCK format at end of file:
    // ... [PCK data] [8-byte PCK size] [4-byte magic "GDPC"]
    // Total trailer: 12 bytes

    if file_length < 12 {
        bail!("File too small to contain embedded PCK");
    }

    // Read magic at end (last 4 bytes)
    reader
        .seek(SeekFrom::End(-4))
        .context("seeking to end magic")?;
    let end_magic = read_u32_le(reader).context("reading end magic")?;

    if end_magic != PCK_HEADER_MAGIC {
        bail!("Not a Godot PCK file (no magic at start or end)");
    }

    // Read PCK size (8 bytes before the end magic)
    reader
        .seek(SeekFrom::End(-12))
        .context("seeking to pck size")?;
    let pck_size = read_u64_le(reader).context("reading embedded pck size")?;

    // Calculate PCK start position
    // pck_size is the size of the PCK data (excluding the 12-byte trailer)
    // PCK starts at: file_length - 12 - pck_size
    let pck_end = file_length - 12; // End of PCK data (before trailer)

    let pck_start = pck_end
        .checked_sub(pck_size)
        .context("embedded pck size larger than file")?;

    // Verify magic at calculated PCK start
    reader
        .seek(SeekFrom::Start(pck_start))
        .context("seeking to embedded pck start")?;
    let start_magic = read_u32_le(reader).context("reading embedded pck magic")?;

    if start_magic != PCK_HEADER_MAGIC {
        bail!(
            "Invalid embedded PCK: magic not found at calculated start position (offset {})",
            pck_start
        );
    }

    // Seek back to PCK start for subsequent reading
    reader
        .seek(SeekFrom::Start(pck_start))
        .context("seeking back to pck start")?;

    Ok((pck_start, pck_end, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_filter_override_wins_over_exclude() {
        let filter = FileFilter::from_cli(
            None,
            None,
            &[],
            &["secret".to_string()],
            &["secret".to_string()],
        )
        .unwrap();

        assert!(filter.include("res://secret.txt", 123));
    }

    #[test]
    fn file_filter_include_requires_match_when_configured() {
        let filter = FileFilter::from_cli(None, None, &["\\.txt$".to_string()], &[], &[]).unwrap();

        assert!(filter.include("res://a.txt", 1));
        assert!(!filter.include("res://a.png", 1));
    }

    #[test]
    fn file_filter_size_limits_apply() {
        let filter = FileFilter::from_cli(Some(10), Some(20), &[], &[], &[]).unwrap();

        assert!(!filter.include("res://small.bin", 9));
        assert!(filter.include("res://ok.bin", 10));
        assert!(filter.include("res://ok2.bin", 20));
        assert!(!filter.include("res://big.bin", 21));
    }

    #[test]
    fn entry_path_to_relative_strips_prefixes_and_slashes() {
        assert_eq!(
            entry_path_to_relative("res://a/b.txt"),
            PathBuf::from("a/b.txt")
        );
        assert_eq!(
            entry_path_to_relative("user://a/b.txt"),
            PathBuf::from("@@user@@/a/b.txt")
        );
        assert_eq!(entry_path_to_relative("/a/b.txt"), PathBuf::from("a/b.txt"));
        assert_eq!(entry_path_to_relative("a/b.txt"), PathBuf::from("a/b.txt"));
    }
}
