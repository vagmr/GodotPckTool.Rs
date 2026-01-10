use std::path::PathBuf;

use clap::Parser;

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

    #[arg(short = 'v', long = "version")]
    version: bool,

    #[arg(value_name = "files")]
    positional_files: Vec<String>,
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

    if let Err(message) = parse_godot_version(&args.set_godot_version) {
        println!("ERROR: specified version number is invalid: {message}");
        return 1;
    }

    let mut files = args.files;
    files.extend(args.positional_files);

    let pack = match args.pack {
        Some(pack) => pack,
        None => {
            if files.is_empty() {
                println!("ERROR: No pck file or list of files given");
                return 1;
            }

            let pack = PathBuf::from(files.remove(0));
            pack
        }
    };

    let filter = match godotpck::FileFilter::from_cli(
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

    match args.action.as_str() {
        "list" | "l" => list_action(&pack, &filter, args.print_hashes),
        "extract" | "e" => extract_action(&pack, &filter, args.output.as_ref(), !args.quieter),
        _ => {
            println!("ERROR: unknown action: {}", args.action);
            1
        }
    }
}

fn list_action(pack: &PathBuf, filter: &godotpck::FileFilter, print_hashes: bool) -> i32 {
    if !pack.exists() {
        println!(
            "ERROR: specified pck file doesn't exist: {}",
            pack.display()
        );
        return 2;
    }

    let pck = match godotpck::PckFile::load(pack, Some(filter)) {
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
    filter: &godotpck::FileFilter,
    output: Option<&PathBuf>,
    print_extracted: bool,
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

    let pck = match godotpck::PckFile::load(pack, Some(filter)) {
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
