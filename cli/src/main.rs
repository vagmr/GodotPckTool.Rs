use std::fs;
use std::io::Read;
use std::path::PathBuf;

use clap::Parser;
use serde_json::Value;

#[derive(Parser, Debug)]
#[command(
    name = "godotpcktool",
    about = "Godot .pck file extractor and packer",
    disable_version_flag = true
)]
struct Args {
    #[arg(short = 'p', long = "pack")]
    pack: Option<PathBuf>,

    #[arg(short = 'a', long = "action", default_value = "list")]
    action: String,

    #[arg(short = 'f', long = "file", value_delimiter = ',')]
    files: Vec<String>,

    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,

    #[arg(long = "remove-prefix")]
    remove_prefix: Option<String>,

    #[arg(long = "command-file")]
    command_file: Option<PathBuf>,

    #[arg(long = "set-godot-version", default_value = "4.0.0")]
    set_godot_version: String,

    #[arg(long = "min-size-filter")]
    min_size_filter: Option<u64>,

    #[arg(long = "max-size-filter")]
    max_size_filter: Option<u64>,

    #[arg(short = 'i', long = "include-regex-filter", value_delimiter = ',')]
    include_regex_filter: Vec<String>,

    #[arg(short = 'e', long = "exclude-regex-filter", value_delimiter = ',')]
    exclude_regex_filter: Vec<String>,

    #[arg(long = "include-override-filter", value_delimiter = ',')]
    include_override_filter: Vec<String>,

    #[arg(short = 'q', long = "quieter")]
    quieter: bool,

    #[arg(long = "print-hashes")]
    print_hashes: bool,

    /// 32-byte hex string (64 characters) for encrypted PCK files (reading)
    #[arg(short = 'k', long = "encryption-key")]
    encryption_key: Option<String>,

    /// Encryption key for creating encrypted PCK files (64 hex characters)
    /// Use with --encrypt-index and/or --encrypt-files
    #[arg(short = 'K', long = "encrypt-key")]
    encrypt_key: Option<String>,

    /// Encrypt the file index when creating PCK (requires --encrypt-key)
    #[arg(long = "encrypt-index")]
    encrypt_index: bool,

    /// Encrypt file contents when creating PCK (requires --encrypt-key)
    #[arg(long = "encrypt-files")]
    encrypt_files: bool,

    /// Executable file to scan for encryption key (for bruteforce action)
    #[arg(long = "exe")]
    exe: Option<PathBuf>,

    /// Start address for bruteforce scan (default: 0)
    #[arg(long = "start-address")]
    start_address: Option<u64>,

    /// End address for bruteforce scan (default: file size)
    #[arg(long = "end-address")]
    end_address: Option<u64>,

    /// Number of threads for bruteforce (default: CPU cores)
    #[arg(long = "threads")]
    threads: Option<usize>,

    /// Base PCK file for patch operation (overlay files onto this PCK)
    #[arg(long = "base-pck")]
    base_pck: Option<PathBuf>,

    /// Path prefix to add to patch files (e.g., "mods/")
    #[arg(long = "path-prefix")]
    path_prefix: Option<String>,

    #[arg(short = 'v', long = "version")]
    version: bool,

    #[arg(value_name = "files")]
    positional_files: Vec<String>,
}

#[derive(Debug, Clone)]
struct FileEntry {
    input_file: String,
    target: Option<String>,
}

struct AddActionArgs<'a> {
    pack: &'a PathBuf,
    filter: &'a godotpck_rs::FileFilter,
    remove_prefix: Option<&'a str>,
    quieter: bool,
    file_entries: &'a [FileEntry],
    requested_godot_version: godotpck_rs::GodotVersion,
    encryption_key: Option<[u8; 32]>,
    encrypt_key: Option<[u8; 32]>,
    encrypt_index: bool,
    encrypt_files: bool,
}

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let args = Args::parse();

    if args.version {
        println!("GodotPckTool version {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }

    let (godot_major, godot_minor, godot_patch) = match parse_godot_version(&args.set_godot_version)
    {
        Ok(v) => v,
        Err(message) => {
            println!("ERROR: specified version number is invalid: {message}");
            return 1;
        }
    };

    let requested_godot_version = godotpck_rs::GodotVersion {
        major: godot_major,
        minor: godot_minor,
        patch: godot_patch,
    };

    let filter = match godotpck_rs::FileFilter::from_cli(
        args.min_size_filter,
        args.max_size_filter,
        &args.include_regex_filter,
        &args.exclude_regex_filter,
        &args.include_override_filter,
    ) {
        Ok(filter) => filter,
        Err(e) => {
            println!("ERROR: invalid regex: {e}");
            return 1;
        }
    };

    // Parse encryption key if provided (for reading encrypted PCK)
    let encryption_key = match &args.encryption_key {
        Some(hex) => match godotpck_rs::parse_hex_key(hex) {
            Ok(key) => Some(key),
            Err(e) => {
                println!("ERROR: invalid encryption key: {e}");
                return 1;
            }
        },
        None => None,
    };

    // Parse encryption key for creating encrypted PCK
    let encrypt_key = match &args.encrypt_key {
        Some(hex) => match godotpck_rs::parse_hex_key(hex) {
            Ok(key) => Some(key),
            Err(e) => {
                println!("ERROR: invalid encrypt key: {e}");
                return 1;
            }
        },
        None => None,
    };

    // Validate encryption options
    if (args.encrypt_index || args.encrypt_files) && encrypt_key.is_none() {
        println!("ERROR: --encrypt-index and --encrypt-files require --encrypt-key");
        return 1;
    }

    let mut files = args.files;
    files.extend(args.positional_files);

    let mut file_commands: Value = Value::Null;

    {
        let mut already_read = false;
        let mut idx = 0;
        while idx < files.len() {
            if files[idx] != "-" || already_read {
                idx += 1;
                continue;
            }

            already_read = true;
            files.remove(idx);

            println!("Reading JSON file commands from STDIN until EOF...");

            let mut data = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut data) {
                println!("ERROR: invalid json: {e}");
                return 1;
            }

            println!("Finished reading STDIN (total characters: {}).", data.len());

            match serde_json::from_str::<Value>(&data) {
                Ok(parsed) => file_commands = parsed,
                Err(e) => {
                    println!("ERROR: invalid json: {e}");
                    return 1;
                }
            }
        }
    }

    if let Some(command_file) = &args.command_file {
        println!(
            "Reading JSON commands from file: {}",
            command_file.display()
        );

        let data = match fs::read_to_string(command_file) {
            Ok(data) => data,
            Err(_) => {
                println!("ERROR: invalid json file: failed to open the command file");
                return 1;
            }
        };

        let parsed = match serde_json::from_str::<Value>(&data) {
            Ok(parsed) => parsed,
            Err(e) => {
                println!("ERROR: invalid json file: {e}");
                return 1;
            }
        };

        let Value::Array(mut parsed_array) = parsed else {
            println!(
                "ERROR: invalid json file: expected JSON file to contain a single JSON array with objects in it"
            );
            return 1;
        };

        if !file_commands.is_array() {
            file_commands = Value::Array(Vec::new());
        }

        if let Value::Array(dest) = &mut file_commands {
            dest.append(&mut parsed_array);
        }
    }

    let mut file_entries: Vec<FileEntry> = files
        .into_iter()
        .map(|file| FileEntry {
            input_file: file,
            target: None,
        })
        .collect();

    if let Value::Array(entries) = &file_commands {
        for entry in entries {
            let file = entry.get("file").and_then(|v| v.as_str());
            let target = entry.get("target").and_then(|v| v.as_str());

            let (Some(file), Some(target)) = (file, target) else {
                println!(
                    "ERROR: unexpected JSON object format in array: invalid or missing fields"
                );
                println!("Incorrect object:");
                println!("{entry}");
                return 1;
            };

            file_entries.push(FileEntry {
                input_file: file.to_string(),
                target: Some(target.to_string()),
            });
        }
    }

    let pack = match args.pack {
        Some(pack) => pack,
        None => {
            if file_entries.is_empty() {
                println!("ERROR: No pck file or list of files given");
                return 1;
            }

            PathBuf::from(file_entries.remove(0).input_file)
        }
    };

    match args.action.as_str() {
        "list" | "l" => list_action(&pack, &filter, args.print_hashes, encryption_key),
        "extract" | "e" => extract_action(
            &pack,
            &filter,
            args.output.as_ref(),
            !args.quieter,
            encryption_key,
        ),
        "repack" | "r" => repack_action(&pack, &filter, &file_entries, encryption_key),
        "add" | "a" => add_action(AddActionArgs {
            pack: &pack,
            filter: &filter,
            remove_prefix: args.remove_prefix.as_deref(),
            quieter: args.quieter,
            file_entries: &file_entries,
            requested_godot_version,
            encryption_key,
            encrypt_key,
            encrypt_index: args.encrypt_index,
            encrypt_files: args.encrypt_files,
        }),
        "bruteforce" | "bf" => bruteforce_action(
            &pack,
            args.exe.as_ref(),
            args.start_address,
            args.end_address,
            args.threads,
        ),
        "rip" => rip_action(&pack, args.output.as_ref(), encryption_key),
        "merge" => merge_action(&pack, args.exe.as_ref(), encryption_key),
        "remove" => remove_action(&pack, encryption_key),
        "split" => split_action(&pack, args.output.as_ref(), encryption_key),
        "change-version" | "cv" => change_version_action(
            &pack,
            args.output.as_ref(),
            &requested_godot_version,
            encryption_key,
        ),
        "patch" => patch_action(
            args.base_pck.as_ref(),
            &file_entries,
            args.output.as_ref(),
            args.remove_prefix.as_deref(),
            args.path_prefix.as_deref(),
            Some(&requested_godot_version),
            encryption_key,
            &filter,
        ),
        _ => {
            println!("ERROR: unknown action: {}", args.action);
            1
        }
    }
}

fn list_action(
    pack: &PathBuf,
    filter: &godotpck_rs::FileFilter,
    print_hashes: bool,
    encryption_key: Option<[u8; 32]>,
) -> i32 {
    if !pack.exists() {
        println!(
            "ERROR: specified pck file doesn't exist: {}",
            pack.display()
        );
        return 2;
    }

    let pck = match godotpck_rs::PckFile::load(pack, Some(filter), encryption_key) {
        Ok(pck) => pck,
        Err(e) => {
            println!("ERROR: couldn't load pck file: {}", pack.display());
            println!("{e:#}");
            return 2;
        }
    };

    if pck.excluded_by_filter() > 0 {
        println!(
            "{} files excluded by filters: {}",
            pack.display(),
            pck.excluded_by_filter()
        );
    }

    let header = pck.header();
    println!(
        "Pck version: {}, Godot: {}",
        header.format_version,
        header.godot_version_string()
    );
    println!("Contents of '{}':", pack.display());

    pck.print_file_list(print_hashes);

    println!("end of contents.");
    0
}

fn extract_action(
    pack: &PathBuf,
    filter: &godotpck_rs::FileFilter,
    output: Option<&PathBuf>,
    print_extracted: bool,
    encryption_key: Option<[u8; 32]>,
) -> i32 {
    if !pack.exists() {
        println!(
            "ERROR: specified pck file doesn't exist: {}",
            pack.display()
        );
        return 2;
    }

    let Some(output) = output else {
        println!("ERROR: no output folder specified");
        return 1;
    };

    let pck = match godotpck_rs::PckFile::load(pack, Some(filter), encryption_key) {
        Ok(pck) => pck,
        Err(e) => {
            println!("ERROR: couldn't load pck file: {}", pack.display());
            println!("{e:#}");
            return 2;
        }
    };

    if pck.excluded_by_filter() > 0 {
        println!(
            "{} files excluded by filters: {}",
            pack.display(),
            pck.excluded_by_filter()
        );
    }

    println!("Extracting to: {}", output.display());

    if let Err(e) = pck.extract(output, print_extracted) {
        println!("ERROR: extraction failed");
        println!("{e:#}");
        return 2;
    }

    println!("Extraction completed");
    0
}

fn repack_action(
    pack: &PathBuf,
    filter: &godotpck_rs::FileFilter,
    file_entries: &[FileEntry],
    encryption_key: Option<[u8; 32]>,
) -> i32 {
    if !pack.exists() {
        println!(
            "ERROR: specified pck file doesn't exist: {}",
            pack.display()
        );
        return 2;
    }

    let pck = match godotpck_rs::PckFile::load(pack, Some(filter), encryption_key) {
        Ok(pck) => pck,
        Err(_) => {
            println!("ERROR: couldn't load pck file: {}", pack.display());
            return 2;
        }
    };

    if pck.excluded_by_filter() > 0 {
        println!(
            "{} files excluded by filters: {}",
            pack.display(),
            pck.excluded_by_filter()
        );
    }

    let output_path = if file_entries.is_empty() {
        pack.clone()
    } else {
        if file_entries.len() != 1 {
            println!("ERROR: only one target file to repack as is allowed");
            return 1;
        }
        PathBuf::from(&file_entries[0].input_file)
    };

    println!("Repacking to: {}", output_path.display());

    let builder = godotpck_rs::PckBuilder::from_loaded_pck(&pck, &output_path);
    if builder.write().is_err() {
        println!("Failed to repack");
        return 2;
    }

    println!("Repack complete");
    0
}

fn add_action(args: AddActionArgs<'_>) -> i32 {
    let AddActionArgs {
        pack,
        filter,
        remove_prefix,
        quieter,
        file_entries,
        requested_godot_version,
        encryption_key,
        encrypt_key,
        encrypt_index,
        encrypt_files,
    } = args;
    if file_entries.is_empty() {
        println!("ERROR: no files specified");
        return 1;
    }

    let mut builder = if pack.exists() {
        println!("Target pck exists, loading it before adding new files");

        let pck = match godotpck_rs::PckFile::load(pack, Some(filter), encryption_key) {
            Ok(pck) => pck,
            Err(_) => {
                println!("ERROR: couldn't load existing target pck. Please change the target or delete the existing file.");
                return 2;
            }
        };

        if pck.excluded_by_filter() > 0 {
            println!(
                "{} files excluded by filters: {}",
                pack.display(),
                pck.excluded_by_filter()
            );
        }

        godotpck_rs::PckBuilder::from_loaded_pck(&pck, pack)
    } else {
        godotpck_rs::PckBuilder::new_empty(pack, requested_godot_version)
    };

    // Set encryption settings if provided
    if let Some(key) = encrypt_key {
        if encrypt_index || encrypt_files {
            builder.set_encryption(godotpck_rs::EncryptionSettings::new(
                key,
                encrypt_index,
                encrypt_files,
            ));
            if !quieter {
                println!(
                    "Encryption enabled: index={}, files={}",
                    encrypt_index, encrypt_files
                );
            }
        }
    }

    let strip_prefix = remove_prefix.unwrap_or("");

    for entry in file_entries {
        if let Some(target) = &entry.target {
            let pck_path = godotpck_rs::prepare_pck_path(target, "");
            match builder.add_single_file(&entry.input_file, pck_path.clone(), Some(filter)) {
                Ok(true) => {
                    if !quieter {
                        println!("Adding {} as {}", entry.input_file, pck_path);
                    }
                }
                Ok(false) => {
                    // excluded by filter
                }
                Err(_) => {
                    println!("ERROR: failed to process file to add: {}", entry.input_file);
                    return 3;
                }
            }
        } else {
            match builder.add_files_from_filesystem(&entry.input_file, strip_prefix, Some(filter)) {
                Ok(added) => {
                    if !quieter {
                        for (fs_path, pck_path) in added {
                            println!("Adding {} as {}", fs_path, pck_path);
                        }
                    }
                }
                Err(_) => {
                    println!("ERROR: failed to process file to add: {}", entry.input_file);
                    return 3;
                }
            }
        }
    }

    if builder.write().is_err() {
        println!("Failed to save pck");
        return 2;
    }

    println!("Writing / updating pck finished");
    0
}

fn parse_godot_version(version: &str) -> Result<(u32, u32, u32), String> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid version format, expected format: x.y.z".to_string());
    }

    let major = parts[0]
        .parse::<u32>()
        .map_err(|_| "invalid version format, expected format: x.y.z".to_string())?;
    let minor = parts[1]
        .parse::<u32>()
        .map_err(|_| "invalid version format, expected format: x.y.z".to_string())?;
    let patch = parts[2]
        .parse::<u32>()
        .map_err(|_| "invalid version format, expected format: x.y.z".to_string())?;

    Ok((major, minor, patch))
}

fn bruteforce_action(
    pack: &PathBuf,
    exe: Option<&PathBuf>,
    start_address: Option<u64>,
    end_address: Option<u64>,
    threads: Option<usize>,
) -> i32 {
    let exe_path = match exe {
        Some(p) => p,
        None => {
            println!("ERROR: --exe is required for bruteforce action");
            return 1;
        }
    };

    if !pack.exists() {
        println!(
            "ERROR: specified pck file doesn't exist: {}",
            pack.display()
        );
        return 2;
    }

    if !exe_path.exists() {
        println!(
            "ERROR: specified executable doesn't exist: {}",
            exe_path.display()
        );
        return 2;
    }

    println!("Starting bruteforce search...");
    println!("  PCK file: {}", pack.display());
    println!("  Executable: {}", exe_path.display());

    let mut config = godotpck_rs::BruteforceConfig::default();
    if let Some(start) = start_address {
        config.start_address = start;
        println!("  Start address: 0x{:x}", start);
    }
    if let Some(end) = end_address {
        config.end_address = Some(end);
        println!("  End address: 0x{:x}", end);
    }
    if let Some(t) = threads {
        config.threads = t;
    }
    println!("  Threads: {}", config.threads);
    println!();

    let bruteforcer = godotpck_rs::Bruteforcer::with_config(config);

    // Progress callback
    let progress_cb: godotpck_rs::ProgressCallback = Box::new(|progress| {
        print!(
            "\r[{:6.2}%] Address: 0x{:x} | Speed: {} keys/s | Elapsed: {:?} | ETA: {:?}    ",
            progress.percent,
            progress.current_address,
            progress.keys_per_second,
            progress.elapsed,
            progress.remaining
        );
        use std::io::Write;
        let _ = std::io::stdout().flush();
    });

    match bruteforcer.start(exe_path, pack, Some(progress_cb)) {
        Ok(result) => {
            println!(); // New line after progress
            if result.found {
                println!();
                println!("=== KEY FOUND! ===");
                println!("Key (hex): {}", result.key_hex);
                println!("Address: 0x{:x} ({})", result.address, result.address);
                println!();
                println!("Use this key with: --encryption-key {}", result.key_hex);
                0
            } else {
                println!();
                println!("No matching key found in the specified range.");
                1
            }
        }
        Err(e) => {
            println!();
            println!("ERROR: Bruteforce failed: {:#}", e);
            2
        }
    }
}

fn rip_action(pack: &PathBuf, output: Option<&PathBuf>, encryption_key: Option<[u8; 32]>) -> i32 {
    let output_path = match output {
        Some(p) => p.clone(),
        None => {
            // Default: same name with .pck extension
            let mut out = pack.clone();
            out.set_extension("pck");
            if out == *pack {
                // If already .pck, add _ripped suffix
                let stem = pack.file_stem().unwrap_or_default().to_string_lossy();
                out.set_file_name(format!("{}_ripped.pck", stem));
            }
            out
        }
    };

    if !pack.exists() {
        println!("ERROR: specified file doesn't exist: {}", pack.display());
        return 2;
    }

    println!("Ripping embedded PCK...");
    println!("  Source: {}", pack.display());
    println!("  Output: {}", output_path.display());

    match godotpck_rs::rip_pck(pack, &output_path, encryption_key) {
        Ok(result) => {
            println!();
            println!("Successfully extracted embedded PCK!");
            println!("  PCK size: {} bytes", result.pck_size);
            0
        }
        Err(e) => {
            println!();
            println!("ERROR: Rip failed: {:#}", e);
            2
        }
    }
}

fn merge_action(
    pck_path: &PathBuf,
    exe_path: Option<&PathBuf>,
    encryption_key: Option<[u8; 32]>,
) -> i32 {
    let exe_path = match exe_path {
        Some(p) => p,
        None => {
            println!("ERROR: --exe is required for merge action");
            return 1;
        }
    };

    if !pck_path.exists() {
        println!(
            "ERROR: specified PCK file doesn't exist: {}",
            pck_path.display()
        );
        return 2;
    }

    if !exe_path.exists() {
        println!(
            "ERROR: specified executable doesn't exist: {}",
            exe_path.display()
        );
        return 2;
    }

    println!("Merging PCK into executable...");
    println!("  PCK file: {}", pck_path.display());
    println!("  Executable: {}", exe_path.display());

    match godotpck_rs::merge_pck(pck_path, exe_path, encryption_key) {
        Ok(result) => {
            println!();
            println!("Successfully merged PCK into executable!");
            println!("  Output size: {} bytes", result.output_size);
            println!("  PCK starts at: 0x{:x}", result.pck_start);
            0
        }
        Err(e) => {
            println!();
            println!("ERROR: Merge failed: {:#}", e);
            2
        }
    }
}

fn remove_action(exe_path: &PathBuf, encryption_key: Option<[u8; 32]>) -> i32 {
    if !exe_path.exists() {
        println!(
            "ERROR: specified file doesn't exist: {}",
            exe_path.display()
        );
        return 2;
    }

    println!("Removing embedded PCK from executable...");
    println!("  File: {}", exe_path.display());

    match godotpck_rs::remove_pck(exe_path, encryption_key) {
        Ok(result) => {
            println!();
            println!("Successfully removed embedded PCK!");
            println!("  New file size: {} bytes", result.exe_size);
            println!("  Removed PCK size: {} bytes", result.removed_pck_size);
            0
        }
        Err(e) => {
            println!();
            println!("ERROR: Remove failed: {:#}", e);
            2
        }
    }
}

fn split_action(
    exe_path: &PathBuf,
    output: Option<&PathBuf>,
    encryption_key: Option<[u8; 32]>,
) -> i32 {
    if !exe_path.exists() {
        println!(
            "ERROR: specified file doesn't exist: {}",
            exe_path.display()
        );
        return 2;
    }

    // Determine output paths
    let (output_exe, output_pck) = match output {
        Some(p) => {
            let mut pck = p.clone();
            pck.set_extension("pck");
            (Some(p.clone()), Some(pck))
        }
        None => (None, None),
    };

    println!("Splitting embedded PCK from executable...");
    println!("  Source: {}", exe_path.display());
    if let Some(ref exe) = output_exe {
        println!("  Output EXE: {}", exe.display());
    }
    if let Some(ref pck) = output_pck {
        println!("  Output PCK: {}", pck.display());
    }

    match godotpck_rs::split_pck(
        exe_path,
        output_exe.as_ref(),
        output_pck.as_ref(),
        encryption_key,
    ) {
        Ok(result) => {
            println!();
            println!("Successfully split embedded PCK!");
            println!("  EXE size: {} bytes", result.exe_size);
            println!("  PCK size: {} bytes", result.pck_size);
            0
        }
        Err(e) => {
            println!();
            println!("ERROR: Split failed: {:#}", e);
            2
        }
    }
}

fn change_version_action(
    pck_path: &PathBuf,
    output_path: Option<&PathBuf>,
    new_version: &godotpck_rs::GodotVersion,
    encryption_key: Option<[u8; 32]>,
) -> i32 {
    if !pck_path.exists() {
        println!(
            "ERROR: specified PCK file doesn't exist: {}",
            pck_path.display()
        );
        return 2;
    }

    println!("Changing PCK version...");
    println!("  Input: {}", pck_path.display());
    println!(
        "  Target version: {}.{}.{}",
        new_version.major, new_version.minor, new_version.patch
    );

    if let Some(out) = output_path {
        println!("  Output: {}", out.display());
    } else {
        println!("  Output: {} (in-place)", pck_path.display());
    }

    let output: Option<&std::path::Path> = output_path.map(|p| p.as_path());

    match godotpck_rs::change_version(
        pck_path,
        (new_version.major, new_version.minor, new_version.patch),
        output,
        encryption_key,
    ) {
        Ok(result) => {
            println!();
            println!("Successfully changed PCK version!");
            println!(
                "  Version: {} -> {}",
                result.old_version, result.new_version
            );
            println!(
                "  Format: v{} -> v{}",
                result.old_format_version, result.new_format_version
            );
            println!("  Files: {}", result.file_count);
            0
        }
        Err(e) => {
            println!();
            println!("ERROR: Change version failed: {:#}", e);
            2
        }
    }
}

fn patch_action(
    base_pck: Option<&PathBuf>,
    file_entries: &[FileEntry],
    output_path: Option<&PathBuf>,
    strip_prefix: Option<&str>,
    path_prefix: Option<&str>,
    godot_version: Option<&godotpck_rs::GodotVersion>,
    encryption_key: Option<[u8; 32]>,
    filter: &godotpck_rs::FileFilter,
) -> i32 {
    // Validate required arguments
    let base_pck = match base_pck {
        Some(p) => p,
        None => {
            println!("ERROR: --base-pck is required for patch action");
            return 1;
        }
    };

    if !base_pck.exists() {
        println!("ERROR: Base PCK file doesn't exist: {}", base_pck.display());
        return 2;
    }

    let output_path = match output_path {
        Some(p) => p,
        None => {
            println!("ERROR: --output is required for patch action");
            return 1;
        }
    };

    // Get patch directory from file_entries (first entry)
    let patch_dir = if file_entries.is_empty() {
        println!(
            "ERROR: No patch directory specified. Use -f <directory> to specify the patch files."
        );
        return 1;
    } else {
        PathBuf::from(&file_entries[0].input_file)
    };

    if !patch_dir.exists() {
        println!(
            "ERROR: Patch directory doesn't exist: {}",
            patch_dir.display()
        );
        return 2;
    }

    if !patch_dir.is_dir() {
        println!(
            "ERROR: Patch path is not a directory: {}",
            patch_dir.display()
        );
        return 2;
    }

    println!("Creating patched PCK...");
    println!("  Base PCK: {}", base_pck.display());
    println!("  Patch directory: {}", patch_dir.display());
    println!("  Output: {}", output_path.display());

    if let Some(prefix) = strip_prefix {
        println!("  Strip prefix: {}", prefix);
    }
    if let Some(prefix) = path_prefix {
        println!("  Path prefix: {}", prefix);
    }

    let version_tuple = godot_version.map(|v| (v.major, v.minor, v.patch));

    match godotpck_rs::patch_pck(
        base_pck,
        &patch_dir,
        output_path,
        strip_prefix.unwrap_or(""),
        path_prefix.unwrap_or(""),
        version_tuple,
        encryption_key,
        Some(filter),
    ) {
        Ok(result) => {
            println!();
            println!("Successfully created patched PCK!");
            println!("  Base files: {}", result.base_file_count);
            println!("  Patch files: {}", result.patch_file_count);
            println!("  Total files: {}", result.total_file_count);
            println!("  Replaced: {}", result.replaced_files.len());
            println!("  New: {}", result.new_files.len());

            if !result.replaced_files.is_empty() {
                println!();
                println!("Replaced files:");
                for f in &result.replaced_files {
                    println!("  - {}", f);
                }
            }

            if !result.new_files.is_empty() {
                println!();
                println!("New files:");
                for f in &result.new_files {
                    println!("  + {}", f);
                }
            }

            0
        }
        Err(e) => {
            println!();
            println!("ERROR: Patch failed: {:#}", e);
            2
        }
    }
}
