use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::{
    FileFilter, GodotVersion, PckFile, GODOT_RES_PATH, PACK_DIR_ENCRYPTED, PCK_FILE_ENCRYPTED,
    PCK_FILE_RELATIVE_BASE,
};
use anyhow::{bail, Context, Result};
use md5::{Digest, Md5};
use walkdir::WalkDir;

const MAX_SUPPORTED_PCK_VERSION_SAVE: u32 = 3;

/// Encryption settings for creating encrypted PCK files
#[derive(Debug, Clone, Default)]
pub struct EncryptionSettings {
    /// 32-byte encryption key
    pub key: Option<[u8; 32]>,
    /// Whether to encrypt the index (file list)
    pub encrypt_index: bool,
    /// Whether to encrypt file contents
    pub encrypt_files: bool,
}

impl EncryptionSettings {
    /// Create new encryption settings with the given key
    pub fn new(key: [u8; 32], encrypt_index: bool, encrypt_files: bool) -> Self {
        Self {
            key: Some(key),
            encrypt_index,
            encrypt_files,
        }
    }

    /// Check if any encryption is enabled
    pub fn is_enabled(&self) -> bool {
        self.key.is_some() && (self.encrypt_index || self.encrypt_files)
    }
}

#[derive(Debug, Clone)]
pub struct BuildEntry {
    pub path: String,
    /// Original/plaintext file size (stored in index)
    pub size: u64,
    /// Actual size in PCK file (for encrypted files: header + aligned ciphertext)
    pub actual_size: u64,
    pub flags: u32,
    /// Original MD5 from source PCK (for encrypted files, we preserve this)
    pub original_md5: Option<[u8; 16]>,
    pub source: EntrySource,
}

#[derive(Debug, Clone)]
pub enum EntrySource {
    ExistingPck { offset: u64 },
    Filesystem { path: PathBuf },
}

#[derive(Debug, Clone)]
pub struct PckBuilder {
    output_path: PathBuf,
    source_pck_path: Option<PathBuf>,

    format_version: u32,
    godot_version: GodotVersion,

    entries: BTreeMap<String, BuildEntry>,

    alignment: u64,
    pad_paths_to_multiple_with_nulls: usize,

    original_flags: u32,

    /// Encryption settings for creating encrypted PCK files
    encryption: EncryptionSettings,
}

impl PckBuilder {
    pub fn new_empty(output_path: impl AsRef<Path>, godot_version: GodotVersion) -> Self {
        let mut builder = Self {
            output_path: output_path.as_ref().to_path_buf(),
            source_pck_path: None,

            format_version: 2,
            godot_version,

            entries: BTreeMap::new(),

            alignment: 0,
            pad_paths_to_multiple_with_nulls: 4,

            original_flags: 0,

            encryption: EncryptionSettings::default(),
        };

        builder.set_godot_version(
            godot_version.major,
            godot_version.minor,
            godot_version.patch,
        );
        builder
    }

    pub fn from_loaded_pck(pck: &PckFile, output_path: impl AsRef<Path>) -> Self {
        let mut entries = BTreeMap::new();
        for e in pck.entries() {
            // Calculate actual size for encrypted files
            // Encrypted file format: header(40) + align16(plaintext_size)
            let actual_size = if e.flags & crate::PCK_FILE_ENCRYPTED != 0 {
                crate::ENCRYPTED_HEADER_SIZE as u64 + crate::crypto::align_to_16(e.size)
            } else {
                e.size
            };

            entries.insert(
                e.path.clone(),
                BuildEntry {
                    path: e.path.clone(),
                    size: e.size,
                    actual_size,
                    flags: e.flags,
                    original_md5: Some(e.md5),
                    source: EntrySource::ExistingPck { offset: e.offset },
                },
            );
        }

        let header = pck.header();

        Self {
            output_path: output_path.as_ref().to_path_buf(),
            source_pck_path: Some(pck.path().to_path_buf()),

            format_version: header.format_version,
            godot_version: header.godot_version,

            entries,

            alignment: 0,
            pad_paths_to_multiple_with_nulls: 4,

            original_flags: header.flags,

            encryption: EncryptionSettings::default(),
        }
    }

    /// Set encryption settings for the PCK file
    pub fn set_encryption(&mut self, encryption: EncryptionSettings) {
        self.encryption = encryption;
    }

    /// Set encryption with key, index encryption, and file encryption options
    pub fn with_encryption(
        mut self,
        key: [u8; 32],
        encrypt_index: bool,
        encrypt_files: bool,
    ) -> Self {
        self.encryption = EncryptionSettings::new(key, encrypt_index, encrypt_files);
        self
    }

    pub fn set_godot_version(&mut self, major: u32, minor: u32, patch: u32) {
        self.godot_version = GodotVersion {
            major,
            minor,
            patch,
        };

        if major <= 3 {
            self.format_version = 1;
        } else {
            self.format_version = 2;
            if major >= 4 && minor >= 5 {
                self.format_version = 3;
            }
        }
    }

    pub fn output_path(&self) -> &Path {
        &self.output_path
    }

    pub fn add_single_file(
        &mut self,
        filesystem_path: impl AsRef<Path>,
        pck_path: String,
        filter: Option<&FileFilter>,
    ) -> Result<bool> {
        self.add_single_file_with_flags(filesystem_path, pck_path, 0, filter)
    }

    /// Add a single file with explicit flags (e.g., for removal entries).
    pub fn add_single_file_with_flags(
        &mut self,
        filesystem_path: impl AsRef<Path>,
        pck_path: String,
        flags: u32,
        filter: Option<&FileFilter>,
    ) -> Result<bool> {
        let filesystem_path = filesystem_path.as_ref();

        let metadata = fs::metadata(filesystem_path)
            .with_context(|| format!("reading file metadata: {}", filesystem_path.display()))?;
        if !metadata.is_file() {
            bail!("not a file: {}", filesystem_path.display());
        }

        let size = metadata.len();

        if let Some(filter) = filter {
            if !filter.include(&pck_path, size) {
                return Ok(false);
            }
        }

        self.entries.insert(
            pck_path.clone(),
            BuildEntry {
                path: pck_path,
                size,
                actual_size: size, // For new files from filesystem, actual_size == size
                flags,
                original_md5: None, // Will be computed during write
                source: EntrySource::Filesystem {
                    path: filesystem_path.to_path_buf(),
                },
            },
        );

        Ok(true)
    }

    /// Add files from filesystem with version-aware path handling.
    /// This method uses the builder's godot_version to determine path format.
    pub fn add_files_from_filesystem(
        &mut self,
        root: &str,
        strip_prefix: &str,
        filter: Option<&FileFilter>,
    ) -> Result<Vec<(String, String)>> {
        let root_path = PathBuf::from(root);
        if !root_path.exists() {
            bail!("path doesn't exist: {root}");
        }

        let mut added = Vec::new();
        let version = Some(self.godot_version);

        if root_path.is_file() {
            let (pck_path, is_removal) = prepare_pck_path_versioned(root, strip_prefix, version);
            let flags = if is_removal {
                crate::PCK_FILE_DELETED
            } else {
                0
            };
            if self.add_single_file_with_flags(&root_path, pck_path.clone(), flags, filter)? {
                added.push((root.to_string(), pck_path));
            }
            return Ok(added);
        }

        if !root_path.is_dir() {
            bail!("path is neither a file nor a directory: {root}");
        }

        for entry in WalkDir::new(&root_path) {
            let entry = entry.with_context(|| format!("walking directory: {root}"))?;
            if entry.file_type().is_dir() {
                continue;
            }

            let fs_path = entry.path();
            let fs_path_string = fs_path.to_string_lossy();
            let (pck_path, is_removal) =
                prepare_pck_path_versioned(&fs_path_string, strip_prefix, version);
            let flags = if is_removal {
                crate::PCK_FILE_DELETED
            } else {
                0
            };

            if self.add_single_file_with_flags(fs_path, pck_path.clone(), flags, filter)? {
                added.push((fs_path_string.to_string(), pck_path));
            }
        }

        Ok(added)
    }

    pub fn write(&self) -> Result<()> {
        if self.format_version > MAX_SUPPORTED_PCK_VERSION_SAVE {
            bail!("cannot save pck version: {}", self.format_version);
        }

        // Encryption requires format version >= 2
        if self.encryption.is_enabled() && self.format_version < 2 {
            bail!("Encryption requires PCK format version >= 2 (Godot 4+)");
        }

        let mut alignment = self.alignment;
        if self.format_version >= 2 && alignment < 1 {
            alignment = 32;
        }

        let output_path_display = self.output_path.to_string_lossy();
        let tmp_write = PathBuf::from(format!("{output_path_display}.write"));

        let mut out = File::create(&tmp_write)
            .with_context(|| format!("file is unwritable: {}", tmp_write.display()))?;

        let use_relative_offset =
            (self.original_flags & PCK_FILE_RELATIVE_BASE != 0) || self.format_version >= 3;

        write_u32_le(&mut out, crate::PCK_HEADER_MAGIC)?;
        write_u32_le(&mut out, self.format_version)?;

        write_u32_le(&mut out, self.godot_version.major)?;
        write_u32_le(&mut out, self.godot_version.minor)?;
        write_u32_le(&mut out, self.godot_version.patch)?;

        let mut base_offset_location: u64 = 0;
        let mut directory_offset_location: u64 = 0;

        if self.format_version >= 2 {
            let mut flags = 0u32;
            if use_relative_offset {
                flags |= PCK_FILE_RELATIVE_BASE;
            }
            // Set encryption flag if index encryption is enabled
            if self.encryption.encrypt_index && self.encryption.key.is_some() {
                flags |= PACK_DIR_ENCRYPTED;
            }
            write_u32_le(&mut out, flags)?;

            base_offset_location = out.stream_position()?;
            write_u64_le(&mut out, 0)?;

            if self.format_version >= 3 {
                directory_offset_location = out.stream_position()?;
                write_u64_le(&mut out, 0)?;
            }
        }

        for _ in 0..16 {
            write_u32_le(&mut out, 0)?;
        }

        // For encrypted index, we need to build the index in memory first
        let encrypt_index = self.encryption.encrypt_index && self.encryption.key.is_some();
        let encrypt_files = self.encryption.encrypt_files && self.encryption.key.is_some();

        // Build index data
        let mut index_data = Vec::new();
        let mut header_patch_points: BTreeMap<String, u64> = BTreeMap::new();
        let mut sizes: BTreeMap<String, u64> = BTreeMap::new();

        // Write file count
        let file_count = u32::try_from(self.entries.len()).context("too many entries")?;
        index_data.extend_from_slice(&file_count.to_le_bytes());

        for (path, entry) in &self.entries {
            let path_bytes = path.as_bytes();
            let pad = self.pad_paths_to_multiple_with_nulls;
            let to_write_size = path_bytes.len() + (pad - (path_bytes.len() % pad));
            let padding = to_write_size - path_bytes.len();

            // Path length
            index_data.extend_from_slice(
                &u32::try_from(to_write_size)
                    .context("path too long")?
                    .to_le_bytes(),
            );
            // Path bytes
            index_data.extend_from_slice(path_bytes);
            // Padding
            index_data.extend(std::iter::repeat_n(0, padding));

            // Record position for patching later (relative to index start)
            header_patch_points.insert(path.clone(), index_data.len() as u64);

            // Offset placeholder (8 bytes)
            index_data.extend_from_slice(&[0u8; 8]);
            // Size (8 bytes)
            index_data.extend_from_slice(&entry.size.to_le_bytes());
            // MD5 placeholder (16 bytes)
            index_data.extend_from_slice(&[0u8; 16]);

            if self.format_version >= 2 {
                // Flags - add encryption flag if encrypting files
                let mut file_flags = entry.flags;
                if encrypt_files && matches!(entry.source, EntrySource::Filesystem { .. }) {
                    file_flags |= PCK_FILE_ENCRYPTED;
                }
                index_data.extend_from_slice(&file_flags.to_le_bytes());
            }

            sizes.insert(path.clone(), entry.size);
        }

        // Write index (encrypted or plain)
        let remember = out.stream_position()?;
        if self.format_version >= 3 {
            out.seek(SeekFrom::Start(directory_offset_location))?;
            write_u64_le(&mut out, remember)?;
            out.seek(SeekFrom::Start(remember))?;
        }

        let index_start_pos = out.stream_position()?;
        if encrypt_index {
            let key = self.encryption.key.as_ref().unwrap();
            let encrypted_index = crate::crypto::encrypt_block(&index_data, key);
            out.write_all(&encrypted_index)?;
        } else {
            out.write_all(&index_data)?;
        }

        pad_to_alignment(&mut out, alignment)?;
        let files_start = out.stream_position()?;

        if self.format_version >= 2 {
            out.seek(SeekFrom::Start(base_offset_location))?;
            write_u64_le(&mut out, files_start)?;
            out.seek(SeekFrom::Start(files_start))?;
        }

        let mut source_reader: Option<File> = None;
        if self
            .entries
            .values()
            .any(|e| matches!(e.source, EntrySource::ExistingPck { .. }))
        {
            let source_path = self
                .source_pck_path
                .as_ref()
                .context("missing source pck path for repack")?;
            source_reader = Some(File::open(source_path).with_context(|| {
                format!("opening pck file for repacking: {}", source_path.display())
            })?);
        }

        let mut computed_md5: BTreeMap<String, [u8; 16]> = BTreeMap::new();
        let mut computed_offsets: BTreeMap<String, u64> = BTreeMap::new();

        for (path, entry) in &self.entries {
            pad_to_alignment(&mut out, alignment)?;
            let offset_abs = out.stream_position()?;

            let (copied, md5_bytes) = match &entry.source {
                EntrySource::ExistingPck { offset } => {
                    let reader = source_reader
                        .as_mut()
                        .expect("source_reader should be opened for existing pck entries");
                    reader
                        .seek(SeekFrom::Start(*offset))
                        .with_context(|| format!("seeking to entry offset for {path}"))?;

                    // Use actual_size for copying (includes encryption header + aligned ciphertext)
                    let copy_size = entry.actual_size;
                    let mut hasher = Md5::new();
                    let copied = copy_with_hash(reader, &mut out, copy_size, &mut hasher)
                        .with_context(|| format!("copying entry data for {path}"))?;

                    // For encrypted files, use the original MD5 from the index (plaintext hash)
                    let md5_bytes = if let Some(orig_md5) = entry.original_md5 {
                        orig_md5
                    } else {
                        let md5 = hasher.finalize();
                        let mut bytes = [0u8; 16];
                        bytes.copy_from_slice(&md5[..]);
                        bytes
                    };

                    if copied != copy_size {
                        bail!(
                            "ExistingPck entry data source returned {} bytes, expected {} for {}",
                            copied,
                            copy_size,
                            path
                        );
                    }

                    (copied, md5_bytes)
                }
                EntrySource::Filesystem { path: fs_path } => {
                    // Read file content
                    let file_data = fs::read(fs_path)
                        .with_context(|| format!("reading file: {}", fs_path.display()))?;

                    // Compute MD5 of plaintext
                    let md5_bytes = crate::crypto::compute_md5(&file_data);

                    // Write data (encrypted or plain)
                    let copied = if encrypt_files {
                        let key = self.encryption.key.as_ref().unwrap();
                        let encrypted = crate::crypto::encrypt_block(&file_data, key);
                        out.write_all(&encrypted)?;
                        encrypted.len() as u64
                    } else {
                        out.write_all(&file_data)?;
                        file_data.len() as u64
                    };

                    (copied, md5_bytes)
                }
            };

            let _ = copied; // suppress unused warning

            let offset_to_store = if self.format_version < 2 {
                offset_abs
            } else {
                offset_abs
                    .checked_sub(files_start)
                    .context("offset underflow")?
            };

            computed_md5.insert(path.clone(), md5_bytes);
            computed_offsets.insert(path.clone(), offset_to_store);
        }

        // Patch index with computed offsets and MD5s
        for (path, patch_pos) in &header_patch_points {
            let offset = *computed_offsets
                .get(path)
                .with_context(|| format!("missing computed offset for {path}"))?;
            let size = *sizes
                .get(path)
                .with_context(|| format!("missing size for {path}"))?;
            let md5 = *computed_md5
                .get(path)
                .with_context(|| format!("missing md5 for {path}"))?;

            // Patch in index_data buffer
            let pos = *patch_pos as usize;
            index_data[pos..pos + 8].copy_from_slice(&offset.to_le_bytes());
            index_data[pos + 8..pos + 16].copy_from_slice(&size.to_le_bytes());
            index_data[pos + 16..pos + 32].copy_from_slice(&md5);
        }

        // Re-write the index with patched data
        out.seek(SeekFrom::Start(index_start_pos))?;
        if encrypt_index {
            let key = self.encryption.key.as_ref().unwrap();
            let encrypted_index = crate::crypto::encrypt_block(&index_data, key);
            out.write_all(&encrypted_index)?;
        } else {
            out.write_all(&index_data)?;
        }

        out.flush().context("flush writer")?;
        drop(out);

        // Important on Windows: if we're repacking in-place, make sure the original file isn't
        // still open when we try to replace it.
        drop(source_reader);

        let _ = fs::remove_file(&self.output_path);
        fs::rename(&tmp_write, &self.output_path).with_context(|| {
            format!(
                "replacing output file (from {} to {})",
                tmp_write.display(),
                self.output_path.display()
            )
        })?;

        Ok(())
    }
}

/// Prepare a filesystem path for storage in a PCK file.
///
/// - Strips `strip_prefix` from the beginning of the path
/// - Normalizes path separators to forward slashes
/// - Maps `@@user@@/...` back to `user://...`
/// - Strips `.@@removal@@` suffix and sets the removal flag (caller must handle flag)
/// - For Godot < 4.4: prepends `res://` if no scheme is present
/// - For Godot >= 4.4: stores paths without `res://` prefix (but keeps `user://`)
///
/// Returns `(pck_path, is_removal)` where `is_removal` indicates if the file had the removal tag.
pub fn prepare_pck_path_versioned(
    path: &str,
    strip_prefix: &str,
    godot_version: Option<GodotVersion>,
) -> (String, bool) {
    let mut s = path.to_string();
    if !strip_prefix.is_empty() {
        if let Some(stripped) = s.strip_prefix(strip_prefix) {
            s = stripped.to_string();
        }
    }

    s = s.replace('\\', "/");
    while s.starts_with('/') {
        s.remove(0);
    }

    // Check and strip removal tag
    let is_removal = s.ends_with(crate::GODOT_REMOVAL_TAG);
    if is_removal {
        s = s[..s.len() - crate::GODOT_REMOVAL_TAG.len()].to_string();
    }

    // Godot 4.4+ stores paths without the res:// prefix in the index.
    // For older versions, we prepend res://.
    let use_res_prefix = match godot_version {
        Some(v) => v.major < 4 || (v.major == 4 && v.minor < 4),
        None => true, // Default to old behavior (with res://) for safety
    };

    // Preserve explicit schemes (user:// always; res:// depends on version).
    if s.starts_with(crate::GODOT_USER_PATH) {
        return (s, is_removal);
    }
    if let Some(rest) = s.strip_prefix(crate::GODOT_RES_PATH) {
        if use_res_prefix {
            return (s, is_removal);
        }
        let rest = rest.trim_start_matches('/');
        return (rest.to_string(), is_removal);
    }

    // Handle extracted user paths: @@user@@/... -> user://...
    if let Some(rest) = s.strip_prefix(crate::GODOT_EXTRACT_USER_DIR) {
        let rest = rest.trim_start_matches('/');
        return (format!("{}{}", crate::GODOT_USER_PATH, rest), is_removal);
    }

    if use_res_prefix {
        (format!("{GODOT_RES_PATH}{s}"), is_removal)
    } else {
        (s, is_removal)
    }
}

/// Legacy wrapper for `prepare_pck_path_versioned` that assumes old Godot behavior (with res:// prefix).
/// This is kept for backward compatibility with existing code.
pub fn prepare_pck_path(path: &str, strip_prefix: &str) -> String {
    let (pck_path, _is_removal) = prepare_pck_path_versioned(path, strip_prefix, None);
    pck_path
}

fn pad_to_alignment<W: Write + Seek>(writer: &mut W, alignment: u64) -> Result<()> {
    if alignment == 0 {
        return Ok(());
    }

    while (writer.stream_position()? % alignment) != 0 {
        writer.write_all(&[0])?;
    }

    Ok(())
}

fn write_u32_le<W: Write>(writer: &mut W, value: u32) -> Result<()> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn write_u64_le<W: Write>(writer: &mut W, value: u64) -> Result<()> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn copy_with_hash<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    expected: u64,
    hasher: &mut Md5,
) -> Result<u64> {
    let mut remaining = expected;
    let mut buf = [0u8; 64 * 1024];
    let mut copied = 0u64;

    while remaining > 0 {
        let to_read = remaining.min(buf.len() as u64) as usize;
        let n = reader.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }

        hasher.update(&buf[..n]);
        writer.write_all(&buf[..n])?;

        copied += n as u64;
        remaining -= n as u64;
    }

    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        dir.push(format!("godotpcktool_{prefix}_{nanos}"));
        dir
    }

    #[test]
    fn can_write_and_read_back_simple_pck() {
        let base = unique_temp_dir("write_read");
        fs::create_dir_all(&base).unwrap();

        let input_file = base.join("hello.txt");
        fs::write(&input_file, b"hello world").unwrap();

        let pck_path = base.join("out.pck");
        let mut builder = PckBuilder::new_empty(
            &pck_path,
            GodotVersion {
                major: 4,
                minor: 0,
                patch: 0,
            },
        );

        let added = builder
            .add_single_file(&input_file, prepare_pck_path("hello.txt", ""), None)
            .unwrap();
        assert!(added);

        builder.write().unwrap();

        let loaded = PckFile::load(&pck_path, None, None).unwrap();
        assert_eq!(loaded.entries().count(), 1);

        let extract_dir = base.join("extract");
        loaded.extract(&extract_dir, false).unwrap();

        let extracted = extract_dir.join("hello.txt");
        let data = fs::read(extracted).unwrap();
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn repack_preserves_contents() {
        let base = unique_temp_dir("repack");
        fs::create_dir_all(&base).unwrap();

        let input_file = base.join("a.bin");
        fs::write(&input_file, b"abc").unwrap();

        let pck_path = base.join("orig.pck");
        let mut builder = PckBuilder::new_empty(
            &pck_path,
            GodotVersion {
                major: 4,
                minor: 0,
                patch: 0,
            },
        );
        builder
            .add_single_file(&input_file, prepare_pck_path("a.bin", ""), None)
            .unwrap();
        builder.write().unwrap();

        let loaded = PckFile::load(&pck_path, None, None).unwrap();

        let repacked_path = base.join("repacked.pck");
        let repacker = PckBuilder::from_loaded_pck(&loaded, &repacked_path);
        repacker.write().unwrap();

        let loaded2 = PckFile::load(&repacked_path, None, None).unwrap();
        let extract_dir = base.join("extract2");
        loaded2.extract(&extract_dir, false).unwrap();
        let data = fs::read(extract_dir.join("a.bin")).unwrap();
        assert_eq!(data, b"abc");
    }

    #[test]
    fn prepare_pck_path_versioned_strips_res_prefix_for_godot_4_4_plus() {
        let version = Some(GodotVersion {
            major: 4,
            minor: 4,
            patch: 0,
        });

        let (pck_path, is_removal) = prepare_pck_path_versioned("res://a/b.txt", "", version);
        assert!(!is_removal);
        assert_eq!(pck_path, "a/b.txt");

        let (pck_path, is_removal) =
            prepare_pck_path_versioned("res://a/b.txt.@@removal@@", "", version);
        assert!(is_removal);
        assert_eq!(pck_path, "a/b.txt");

        let (pck_path, is_removal) = prepare_pck_path_versioned("user://a/b.txt", "", version);
        assert!(!is_removal);
        assert_eq!(pck_path, "user://a/b.txt");

        let (pck_path, is_removal) = prepare_pck_path_versioned("res://a/b.txt", "", None);
        assert!(!is_removal);
        assert_eq!(pck_path, "res://a/b.txt");
    }
}
