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
        "add" | "a" => add_action(
            &pack,
            &filter,
            args.remove_prefix.as_deref(),
            args.quieter,
            &file_entries,
            requested_godot_version,
            encryption_key,
            encrypt_key,
            args.encrypt_index,
            args.encrypt_files,
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

fn add_action(
    pack: &PathBuf,
    filter: &godotpck_rs::FileFilter,
    remove_prefix: Option<&str>,
    quieter: bool,
    file_entries: &[FileEntry],
    requested_godot_version: godotpck_rs::GodotVersion,
    encryption_key: Option<[u8; 32]>,
    encrypt_key: Option<[u8; 32]>,
    encrypt_index: bool,
    encrypt_files: bool,
) -> i32 {
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
