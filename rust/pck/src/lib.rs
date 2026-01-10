use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use regex::Regex;

pub const PCK_HEADER_MAGIC: u32 = 0x4350_4447;

pub const PACK_DIR_ENCRYPTED: u32 = 1 << 0;
pub const PCK_FILE_ENCRYPTED: u32 = 1 << 0;
pub const PCK_FILE_DELETED: u32 = 1 << 1;

pub const PCK_FILE_RELATIVE_BASE: u32 = 1 << 1;
pub const PCK_FILE_SPARSE_BUNDLE: u32 = 1 << 2;

pub const MAX_SUPPORTED_PCK_VERSION_LOAD: u32 = 3;
pub const GODOT_PCK_EXTENSION: &str = ".pck";
pub const GODOT_RES_PATH: &str = "res://";

mod write;
pub use write::{prepare_pck_path, BuildEntry, EntrySource, PckBuilder};


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
}
impl PckFile {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(path: impl AsRef<Path>, filter: Option<&FileFilter>) -> Result<Self> {

        let path = path.as_ref().to_path_buf();

        let mut file = File::open(&path)
            .with_context(|| format!("opening pck file for reading: {}", path.display()))?;

        let pck_start = file
            .seek(SeekFrom::Current(0))
            .context("reading start offset")?;

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

        if flags & PACK_DIR_ENCRYPTED != 0 {
            bail!("pck is encrypted");
        }

        if flags & PCK_FILE_SPARSE_BUNDLE != 0 {
            // This matches the old tool: it warns but continues.
            // Keeping this in the library avoids hardcoding stdout here.
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

        let file_count = read_u32_le(&mut file).context("reading file count")?;

        let mut excluded_by_filter = 0usize;
        let mut entries = BTreeMap::new();

        for _ in 0..file_count {
            let path_length = read_u32_le(&mut file).context("reading path length")? as usize;
            let mut path_bytes = vec![0u8; path_length];
            file.read_exact(&mut path_bytes)
                .context("reading path bytes")?;

            while path_bytes.last() == Some(&0) {
                path_bytes.pop();
            }

            let path_string = String::from_utf8_lossy(&path_bytes).to_string();

            let rel_offset = read_u64_le(&mut file).context("reading entry offset")?;
            let size = read_u64_le(&mut file).context("reading entry size")?;

            let mut md5 = [0u8; 16];
            file.read_exact(&mut md5).context("reading entry md5")?;

            let mut entry_flags = 0u32;
            if format_version >= 2 {
                entry_flags = read_u32_le(&mut file).context("reading entry flags")?;
            }

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
            print!("{}", entry.path);
            print!(" size: {}", entry.size);

            if print_hashes {
                print!(" md5: {}", format_md5(entry.md5));
            }

            println!();
        }
    }

    pub fn extract(&self, output_prefix: impl AsRef<Path>, print_extracted: bool) -> Result<()> {
        let output_base = output_prefix.as_ref();

        let mut reader = File::open(&self.path)
            .with_context(|| format!("opening pck file for extracting: {}", self.path.display()))?;

        for entry in self.entries() {
            let relative_path = entry_path_to_relative(&entry.path);
            let target_file = output_base.join(&relative_path);

            if print_extracted {
                println!("Extracting {} to {}", entry.path, target_file.display());
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

            reader
                .seek(SeekFrom::Start(entry.offset))
                .with_context(|| format!("seeking to entry offset for {}", entry.path))?;
            let mut take = std::io::Read::by_ref(&mut reader).take(entry.size);
            let copied = std::io::copy(&mut take, &mut writer)
                .with_context(|| format!("writing entry data for {}", entry.path))?;

            if copied != entry.size {
                bail!("reading file entry content failed (specified offset or data length is too large, pck may be corrupt or malformed)");
            }

            writer.flush().context("flush writer")?;
        }

        Ok(())
    }
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
    let without_prefix = entry_path
        .strip_prefix(GODOT_RES_PATH)
        .unwrap_or(entry_path);
    let without_slashes = without_prefix.trim_start_matches('/');
    PathBuf::from(without_slashes)
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
    fn entry_path_to_relative_strips_res_prefix_and_slashes() {
        assert_eq!(
            entry_path_to_relative("res://a/b.txt"),
            PathBuf::from("a/b.txt")
        );
        assert_eq!(entry_path_to_relative("/a/b.txt"), PathBuf::from("a/b.txt"));
        assert_eq!(entry_path_to_relative("a/b.txt"), PathBuf::from("a/b.txt"));
    }
}
