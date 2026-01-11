//! Embedded PCK operations: rip, merge, remove, split
//!
//! This module provides functionality for working with PCK files embedded in executables.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::{PckFile, PCK_HEADER_MAGIC};

/// Buffer size for file operations (1MB)
const BUFFER_SIZE: usize = 1024 * 1024;

/// Result of a rip operation
#[derive(Debug, Clone)]
pub struct RipResult {
    /// Size of the extracted PCK file
    pub pck_size: u64,
    /// Whether the source was embedded
    pub was_embedded: bool,
}

/// Result of a merge operation
#[derive(Debug, Clone)]
pub struct MergeResult {
    /// Final size of the output file
    pub output_size: u64,
    /// Offset where PCK data starts in the output file
    pub pck_start: u64,
}

/// Result of a remove operation
#[derive(Debug, Clone)]
pub struct RemoveResult {
    /// Size of the resulting file (EXE only)
    pub exe_size: u64,
    /// Size of the removed PCK data
    pub removed_pck_size: u64,
}

/// Result of a split operation
#[derive(Debug, Clone)]
pub struct SplitResult {
    /// Size of the EXE file
    pub exe_size: u64,
    /// Size of the PCK file
    pub pck_size: u64,
}

/// Extract (rip) an embedded PCK from an executable to a standalone PCK file.
///
/// # Arguments
/// * `exe_path` - Path to the executable containing embedded PCK
/// * `output_path` - Path where the standalone PCK will be written
/// * `encryption_key` - Optional encryption key for encrypted PCK
///
/// # Returns
/// * `RipResult` on success
pub fn rip_pck<P1: AsRef<Path>, P2: AsRef<Path>>(
    exe_path: P1,
    output_path: P2,
    encryption_key: Option<[u8; 32]>,
) -> Result<RipResult> {
    let exe_path = exe_path.as_ref();
    let output_path = output_path.as_ref();

    // Load the PCK to get embedded info (we don't need to decrypt the full index)
    let pck =
        PckFile::load(exe_path, None, encryption_key).context("Failed to open source file")?;

    if !pck.is_embedded() {
        bail!("The file is not an embedded PCK. Use copy instead.");
    }

    let pck_start = pck.pck_start();
    let pck_end = pck.pck_end();
    let pck_size = pck_end - pck_start;

    // Open source file for reading
    let mut source = File::open(exe_path)
        .with_context(|| format!("Failed to open source file: {}", exe_path.display()))?;

    // Create output file
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create output directory: {}", parent.display())
            })?;
        }
    }

    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(output_path)
        .with_context(|| format!("Failed to create output file: {}", output_path.display()))?;

    // Copy PCK data from source to output
    source
        .seek(SeekFrom::Start(pck_start))
        .context("Failed to seek to PCK start")?;

    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut remaining = pck_size;

    while remaining > 0 {
        let to_read = std::cmp::min(remaining as usize, BUFFER_SIZE);
        let bytes_read = source
            .read(&mut buffer[..to_read])
            .context("Failed to read from source")?;

        if bytes_read == 0 {
            bail!("Unexpected end of file while reading PCK data");
        }

        output
            .write_all(&buffer[..bytes_read])
            .context("Failed to write to output")?;

        remaining -= bytes_read as u64;
    }

    // Now we need to fix the file base address for the standalone PCK
    // For Godot 4+ with relative file base, no fix needed
    // For Godot 4+ with absolute file base, we need to adjust PCK_FileBase
    // For Godot 3, we need to adjust each file's offset

    let header = pck.header();
    let format_version = header.format_version;
    let flags = header.flags;

    // Check if relative file base flag is set (Godot 4+)
    let is_relative_file_base = flags & crate::PCK_FILE_RELATIVE_BASE != 0;

    if format_version >= 2 && !is_relative_file_base {
        // Godot 4+ with absolute file base - fix the file_offset_base field
        // The file_offset_base is at offset 24 from PCK start (after magic + version fields)
        // Magic(4) + Pack(4) + Major(4) + Minor(4) + Patch(4) + Flags(4) = 24 bytes
        let file_base_offset = 24u64;

        // Read current file base
        output
            .seek(SeekFrom::Start(file_base_offset))
            .context("Failed to seek to file base offset")?;

        let mut buf = [0u8; 8];
        output
            .read_exact(&mut buf)
            .context("Failed to read file base")?;
        let old_file_base = u64::from_le_bytes(buf);

        // Calculate new file base (subtract pck_start since we're now standalone)
        let new_file_base = old_file_base.saturating_sub(pck_start);

        // Write new file base
        output
            .seek(SeekFrom::Start(file_base_offset))
            .context("Failed to seek to file base offset for writing")?;
        output
            .write_all(&new_file_base.to_le_bytes())
            .context("Failed to write new file base")?;
    }
    // For Godot 3 or relative file base, no adjustment needed
    // (Godot 3 stores absolute offsets per-file, but they're relative to PCK start anyway)

    output.flush().context("Failed to flush output")?;

    Ok(RipResult {
        pck_size,
        was_embedded: true,
    })
}

/// Merge a standalone PCK file into an executable.
///
/// # Arguments
/// * `pck_path` - Path to the standalone PCK file
/// * `exe_path` - Path to the executable (will be modified in place)
/// * `encryption_key` - Optional encryption key for encrypted PCK
///
/// # Returns
/// * `MergeResult` on success
pub fn merge_pck<P1: AsRef<Path>, P2: AsRef<Path>>(
    pck_path: P1,
    exe_path: P2,
    encryption_key: Option<[u8; 32]>,
) -> Result<MergeResult> {
    let pck_path = pck_path.as_ref();
    let exe_path = exe_path.as_ref();

    // First, check if the EXE already contains a PCK
    if let Ok(existing_pck) = PckFile::load(exe_path, None, None) {
        if existing_pck.is_embedded() {
            bail!("The executable already contains an embedded PCK. Use remove first.");
        }
    }

    // Load the PCK to verify it's valid and get info
    let pck = PckFile::load(pck_path, None, encryption_key).context("Failed to open PCK file")?;

    if pck.is_embedded() {
        bail!("The PCK file is already embedded. Use rip first to extract it.");
    }

    let pck_start = pck.pck_start();
    let pck_end = pck.pck_end();
    let pck_size = pck_end - pck_start;

    // Open PCK file for reading
    let mut pck_file = File::open(pck_path)
        .with_context(|| format!("Failed to open PCK file: {}", pck_path.display()))?;

    // Open EXE file for appending
    let mut exe_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(exe_path)
        .with_context(|| format!("Failed to open executable: {}", exe_path.display()))?;

    // Seek to end of EXE
    let exe_end = exe_file
        .seek(SeekFrom::End(0))
        .context("Failed to seek to end of executable")?;

    // Align to 8 bytes
    let padding = if exe_end % 8 != 0 {
        8 - (exe_end % 8)
    } else {
        0
    };
    if padding > 0 {
        exe_file
            .write_all(&vec![0u8; padding as usize])
            .context("Failed to write padding")?;
    }

    let embed_start = exe_file
        .stream_position()
        .context("Failed to get embed start position")?;

    // Copy PCK data
    pck_file
        .seek(SeekFrom::Start(pck_start))
        .context("Failed to seek to PCK start")?;

    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut remaining = pck_size;

    while remaining > 0 {
        let to_read = std::cmp::min(remaining as usize, BUFFER_SIZE);
        let bytes_read = pck_file
            .read(&mut buffer[..to_read])
            .context("Failed to read from PCK")?;

        if bytes_read == 0 {
            bail!("Unexpected end of file while reading PCK data");
        }

        exe_file
            .write_all(&buffer[..bytes_read])
            .context("Failed to write to executable")?;

        remaining -= bytes_read as u64;
    }

    // Align end to 8 bytes
    let current_pos = exe_file
        .stream_position()
        .context("Failed to get current position")?;
    let end_padding = if (current_pos - embed_start + 12) % 8 != 0 {
        8 - ((current_pos - embed_start + 12) % 8)
    } else {
        0
    };
    if end_padding > 0 {
        exe_file
            .write_all(&vec![0u8; end_padding as usize])
            .context("Failed to write end padding")?;
    }

    // Write trailer: [PCK size (8 bytes)][Magic (4 bytes)]
    let final_pck_size = exe_file
        .stream_position()
        .context("Failed to get final position")?
        - embed_start;

    exe_file
        .write_all(&final_pck_size.to_le_bytes())
        .context("Failed to write PCK size")?;
    exe_file
        .write_all(&PCK_HEADER_MAGIC.to_le_bytes())
        .context("Failed to write magic")?;

    // Fix file base address if needed
    let header = pck.header();
    let format_version = header.format_version;
    let flags = header.flags;
    let is_relative_file_base = flags & crate::PCK_FILE_RELATIVE_BASE != 0;

    if format_version >= 2 && !is_relative_file_base {
        // Godot 4+ with absolute file base - fix the file_offset_base field
        let file_base_offset = embed_start + 24;

        // Read current file base
        exe_file
            .seek(SeekFrom::Start(file_base_offset))
            .context("Failed to seek to file base offset")?;

        let mut buf = [0u8; 8];
        exe_file
            .read_exact(&mut buf)
            .context("Failed to read file base")?;
        let old_file_base = u64::from_le_bytes(buf);

        // Calculate new file base (add embed_start since we're now embedded)
        let new_file_base = old_file_base + embed_start;

        // Write new file base
        exe_file
            .seek(SeekFrom::Start(file_base_offset))
            .context("Failed to seek to file base offset for writing")?;
        exe_file
            .write_all(&new_file_base.to_le_bytes())
            .context("Failed to write new file base")?;
    }

    let output_size = exe_file
        .stream_position()
        .context("Failed to get output size")?;

    exe_file.flush().context("Failed to flush output")?;

    Ok(MergeResult {
        output_size,
        pck_start: embed_start,
    })
}

/// Remove an embedded PCK from an executable.
///
/// # Arguments
/// * `exe_path` - Path to the executable (will be modified in place)
/// * `encryption_key` - Optional encryption key for encrypted PCK
///
/// # Returns
/// * `RemoveResult` on success
pub fn remove_pck<P: AsRef<Path>>(
    exe_path: P,
    encryption_key: Option<[u8; 32]>,
) -> Result<RemoveResult> {
    let exe_path = exe_path.as_ref();

    // Load the PCK to get embedded info
    let pck = PckFile::load(exe_path, None, encryption_key).context("Failed to open file")?;

    if !pck.is_embedded() {
        bail!("The file does not contain an embedded PCK.");
    }

    let pck_start = pck.pck_start();
    let pck_end = pck.pck_end();
    let pck_size = pck_end - pck_start + 12; // Include trailer

    // Truncate the file at pck_start
    let file = OpenOptions::new()
        .write(true)
        .open(exe_path)
        .with_context(|| format!("Failed to open file: {}", exe_path.display()))?;

    file.set_len(pck_start).context("Failed to truncate file")?;

    Ok(RemoveResult {
        exe_size: pck_start,
        removed_pck_size: pck_size,
    })
}

/// Split an embedded PCK into separate EXE and PCK files.
///
/// # Arguments
/// * `exe_path` - Path to the executable containing embedded PCK
/// * `output_exe_path` - Optional path for the output EXE (if None, modifies in place)
/// * `output_pck_path` - Optional path for the output PCK (if None, uses exe name with .pck extension)
/// * `encryption_key` - Optional encryption key for encrypted PCK
///
/// # Returns
/// * `SplitResult` on success
pub fn split_pck<P1: AsRef<Path>, P2: AsRef<Path>, P3: AsRef<Path>>(
    exe_path: P1,
    output_exe_path: Option<P2>,
    output_pck_path: Option<P3>,
    encryption_key: Option<[u8; 32]>,
) -> Result<SplitResult> {
    let exe_path = exe_path.as_ref();

    // Determine output paths
    let output_exe = match &output_exe_path {
        Some(p) => p.as_ref().to_path_buf(),
        None => exe_path.to_path_buf(),
    };

    let output_pck = match &output_pck_path {
        Some(p) => p.as_ref().to_path_buf(),
        None => {
            let mut pck_path = output_exe.clone();
            pck_path.set_extension("pck");
            pck_path
        }
    };

    // If output_exe is different from exe_path, copy the file first
    if output_exe != exe_path {
        std::fs::copy(exe_path, &output_exe).with_context(|| {
            format!(
                "Failed to copy {} to {}",
                exe_path.display(),
                output_exe.display()
            )
        })?;
    }

    // First, rip the PCK to the output path
    let rip_result = rip_pck(&output_exe, &output_pck, encryption_key)
        .context("Failed to rip PCK from executable")?;

    // Then, remove the PCK from the EXE
    let remove_result =
        remove_pck(&output_exe, encryption_key).context("Failed to remove PCK from executable")?;

    Ok(SplitResult {
        exe_size: remove_result.exe_size,
        pck_size: rip_result.pck_size,
    })
}

/// Result of a change version operation
#[derive(Debug, Clone)]
pub struct ChangeVersionResult {
    /// Original Godot version string
    pub old_version: String,
    /// New Godot version string
    pub new_version: String,
    /// Original PCK format version
    pub old_format_version: u32,
    /// New PCK format version
    pub new_format_version: u32,
    /// Number of files in the PCK
    pub file_count: usize,
}

/// Change the Godot version of a PCK file.
///
/// This operation loads the PCK, changes the version, and rewrites it.
/// The safe approach is used (load + rewrite) to properly handle all
/// version-specific offset rules (Godot 3 vs 4 vs 4.4+).
///
/// # Arguments
/// * `pck_path` - Path to the PCK file to modify
/// * `new_version` - New Godot version (major, minor, patch)
/// * `output_path` - Optional output path. If None, overwrites the original file.
/// * `encryption_key` - Optional encryption key for encrypted PCK
///
/// # Returns
/// * `ChangeVersionResult` on success
///
/// # Example
/// ```ignore
/// // Change a Godot 3 PCK to Godot 4
/// change_version("game.pck", (4, 0, 0), None, None)?;
///
/// // Change version and save to new file
/// change_version("game.pck", (4, 4, 0), Some("game_new.pck"), None)?;
/// ```
pub fn change_version<P1: AsRef<Path>, P2: AsRef<Path>>(
    pck_path: P1,
    new_version: (u32, u32, u32),
    output_path: Option<P2>,
    encryption_key: Option<[u8; 32]>,
) -> Result<ChangeVersionResult> {
    let pck_path = pck_path.as_ref();
    let (new_major, new_minor, new_patch) = new_version;

    // Load the PCK file
    let pck = PckFile::load(pck_path, None, encryption_key).context("Failed to load PCK file")?;

    // Get old version info
    let header = pck.header();
    let old_version = header.godot_version.to_string();
    let old_format_version = header.format_version;

    // Determine output path
    let output = match &output_path {
        Some(p) => p.as_ref().to_path_buf(),
        None => pck_path.to_path_buf(),
    };

    // Create builder from loaded PCK
    let mut builder = crate::PckBuilder::from_loaded_pck(&pck, &output);

    // Set new version
    builder.set_godot_version(new_major, new_minor, new_patch);

    // Get new format version (determined by set_godot_version)
    let new_format_version = if new_major <= 3 {
        1
    } else if new_major >= 4 && new_minor >= 5 {
        3
    } else {
        2
    };

    let new_version_str = format!("{}.{}.{}", new_major, new_minor, new_patch);
    let file_count = pck.entries().count();

    // Write the new PCK
    builder.write().context("Failed to write PCK file")?;

    Ok(ChangeVersionResult {
        old_version,
        new_version: new_version_str,
        old_format_version,
        new_format_version,
        file_count,
    })
}

/// Result of a patch operation
#[derive(Debug, Clone)]
pub struct PatchResult {
    /// Number of files from the base PCK
    pub base_file_count: usize,
    /// Number of new/updated files from the patch directory
    pub patch_file_count: usize,
    /// Number of files in the final PCK (may be less than base + patch due to overlays)
    pub total_file_count: usize,
    /// List of files that were replaced (overlayed)
    pub replaced_files: Vec<String>,
    /// List of new files added
    pub new_files: Vec<String>,
}

/// Create a patched PCK by overlaying files from a directory onto a base PCK.
///
/// This operation loads the base PCK, then adds/replaces files from the patch directory.
/// Files in the patch directory with the same path as files in the base PCK will replace them.
///
/// # Arguments
/// * `base_pck_path` - Path to the base PCK file to patch
/// * `patch_dir` - Directory containing files to overlay onto the base PCK
/// * `output_path` - Path for the output PCK file
/// * `strip_prefix` - Prefix to strip from patch directory paths (e.g., "extracted")
/// * `path_prefix` - Prefix to add to patch file paths (e.g., "res://mods/")
/// * `godot_version` - Optional Godot version override. If None, uses base PCK version.
/// * `encryption_key` - Optional encryption key for encrypted PCK
/// * `filter` - Optional file filter
///
/// # Returns
/// * `PatchResult` on success
///
/// # Example
/// ```ignore
/// // Create a patch PCK
/// patch_pck(
///     "base_game.pck",
///     "mod_files/",
///     "patched_game.pck",
///     "mod_files",
///     "",
///     None,
///     None,
///     None,
/// )?;
/// ```
pub fn patch_pck<P1: AsRef<Path>, P2: AsRef<Path>, P3: AsRef<Path>>(
    base_pck_path: P1,
    patch_dir: P2,
    output_path: P3,
    strip_prefix: &str,
    path_prefix: &str,
    godot_version: Option<(u32, u32, u32)>,
    encryption_key: Option<[u8; 32]>,
    filter: Option<&crate::FileFilter>,
) -> Result<PatchResult> {
    let base_pck_path = base_pck_path.as_ref();
    let patch_dir = patch_dir.as_ref();
    let output_path = output_path.as_ref();

    // Validate paths
    if !base_pck_path.exists() {
        bail!("Base PCK file does not exist: {}", base_pck_path.display());
    }

    if !patch_dir.exists() {
        bail!("Patch directory does not exist: {}", patch_dir.display());
    }

    if !patch_dir.is_dir() {
        bail!("Patch path is not a directory: {}", patch_dir.display());
    }

    if output_path == base_pck_path {
        bail!("Output path cannot be the same as base PCK path");
    }

    // Load the base PCK
    let base_pck =
        PckFile::load(base_pck_path, None, encryption_key).context("Failed to load base PCK")?;

    let base_file_count = base_pck.entries().count();

    // Collect base PCK file paths for comparison
    let base_paths: std::collections::HashSet<String> =
        base_pck.entries().map(|e| e.path.clone()).collect();

    // Create builder from base PCK
    let mut builder = crate::PckBuilder::from_loaded_pck(&base_pck, output_path);

    // Override Godot version if specified
    if let Some((major, minor, patch)) = godot_version {
        builder.set_godot_version(major, minor, patch);
    }

    // Add files from patch directory (will overlay existing files)
    let patch_dir_str = patch_dir.to_string_lossy();

    // Compute effective strip prefix
    let effective_strip = if strip_prefix.is_empty() {
        patch_dir_str.to_string()
    } else {
        strip_prefix.to_string()
    };

    let added_files = builder
        .add_files_from_filesystem(&patch_dir_str, &effective_strip, filter)
        .context("Failed to add patch files")?;

    // Categorize added files
    let mut replaced_files = Vec::new();
    let mut new_files = Vec::new();

    for (_fs_path, pck_path) in &added_files {
        // Apply path prefix if specified
        let final_path = if path_prefix.is_empty() {
            pck_path.clone()
        } else {
            // Ensure path_prefix ends with / and pck_path starts correctly
            let prefix = if path_prefix.ends_with('/') {
                path_prefix.to_string()
            } else {
                format!("{}/", path_prefix)
            };

            // Remove res:// prefix if present, then add prefix
            if let Some(stripped) = pck_path.strip_prefix("res://") {
                format!("res://{}{}", prefix.trim_start_matches("res://"), stripped)
            } else {
                format!("{}{}", prefix, pck_path)
            }
        };

        if base_paths.contains(pck_path) || base_paths.contains(&final_path) {
            replaced_files.push(pck_path.clone());
        } else {
            new_files.push(pck_path.clone());
        }
    }

    let patch_file_count = added_files.len();

    // Write the patched PCK
    builder.write().context("Failed to write patched PCK")?;

    // Count total files in output (base - replaced + patch)
    let total_file_count = base_file_count - replaced_files.len() + patch_file_count;

    Ok(PatchResult {
        base_file_count,
        patch_file_count,
        total_file_count,
        replaced_files,
        new_files,
    })
}
