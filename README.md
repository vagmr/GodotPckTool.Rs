# GodotPckTool.rs 🦀

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**[English](README.md)** | **[中文文档](README_CN.md)**

A fast, cross-platform CLI tool for unpacking and packing Godot `.pck` files, rewritten in Rust.

## ✨ Features

### Core Features

- 📦 **List** contents of `.pck` files
- 📤 **Extract** files from `.pck` archives
- 📥 **Add** files to existing or new `.pck` files
- 🔄 **Repack** entire `.pck` files
- 🎯 **Filter** files by size, name patterns (regex)
- 📋 **JSON bulk operations** for scripting

### 🔐 Encryption Support ()

- **AES-256-CFB encryption/decryption** for encrypted PCK files (Godot 4+)
- **Create encrypted PCK** with index and/or file encryption
- Decrypt both **encrypted index** and **encrypted files**
- **Streaming decryption** for memory-efficient large file handling
- MD5 integrity verification during encryption/decryption

### 📦 Embedded PCK Support ()

- **Auto-detect** embedded PCK in executables (self-contained games)
- Extract PCK data from `.exe` or other executable formats
- Supports both standalone `.pck` and embedded PCK files
- **Rip**: Extract embedded PCK to standalone file
- **Merge**: Embed standalone PCK into executable
- **Remove**: Remove embedded PCK from executable
- **Split**: Separate embedded PCK into EXE + PCK files

### 🔄 Version Management ()

- **Change Version**: Convert PCK between Godot versions (3.x ↔ 4.x ↔ 4.4+)
- Automatic format version adjustment based on Godot version
- Safe rewrite approach handles all offset rules correctly

### 🔧 Patch/Overlay (Mod Support)

- **Patch**: Create mod PCK by overlaying files onto base PCK
- Automatically replaces existing files and adds new ones
- Support for path prefix stripping and adding
- Perfect for game modding workflows

### 🔑 Key Bruteforcer ()

- **Brute-force search** for 32-byte AES-256 encryption keys in executables
- **Multi-threaded** parallel scanning for maximum performance
- **Progress reporting** with ETA and keys/second metrics
- **Cancellable** operations with graceful shutdown

### 🛤️ Path Compatibility ()

- **`user://`** paths extracted to `@@user@@/` directory
- **`.@@removal@@`** suffix for deleted file markers
- **Godot 4.4+** path format compatibility (`res://` prefix handling)

### Platform & Performance

- 🐧 **Cross-platform**: Windows, Linux, macOS
- 🚀 **Fast**: Native Rust performance
- 📦 **Single binary**: No dependencies required

## 📥 Installation

### From Releases

Download the latest binary from the [Releases](https://github.com/vagmr/GodotPckTool/releases) page.

### From Source

```bash
# Clone the repository
git clone https://github.com/vagmr/GodotPckTool.git
cd GodotPckTool

# Build release binary
cargo build --release

# Binary will be at target/release/godotpcktool(.exe)
```

### Using Docker

```bash
# Build image
docker build -t godotpcktool .

# Run
docker run --rm -v /path/to/files:/data godotpcktool -p /data/game.pck -a list
```

## 🚀 Usage

View help:

```bash
godotpcktool --help
```

### Listing Contents

```bash
# Short form (default action is list)
godotpcktool game.pck

# Long form
godotpcktool --pack game.pck --action list

# With MD5 hashes
godotpcktool game.pck --print-hashes
```

### Extracting Contents

```bash
# Extract to 'extracted' folder
godotpcktool game.pck -a e -o extracted

# Long form
godotpcktool --pack game.pck --action extract --output extracted

# Quiet mode (less output)
godotpcktool game.pck -a e -o extracted -q
```

### 🔐 Extracting Encrypted PCK ()

```bash
# Extract encrypted PCK with decryption key
godotpcktool encrypted_game.pck -a e -o extracted --encryption-key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# The key must be 64 hex characters (32 bytes / 256 bits)
# This is the same key used in Godot's export settings
```

> **Note**: The encryption key is the same one configured in Godot's export presets under "Encryption" → "Encryption Key". It should be a 64-character hexadecimal string.

### 🔐 Creating Encrypted PCK ()

```bash
# Create encrypted PCK with both index and file encryption
godotpcktool encrypted.pck -a a files/ --remove-prefix files \
  --encrypt-key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --encrypt-index --encrypt-files

# Encrypt only the file index (file list hidden, but files readable)
godotpcktool encrypted.pck -a a files/ --remove-prefix files \
  --encrypt-key YOUR_64_HEX_CHAR_KEY --encrypt-index

# Encrypt only file contents (file list visible, but contents encrypted)
godotpcktool encrypted.pck -a a files/ --remove-prefix files \
  --encrypt-key YOUR_64_HEX_CHAR_KEY --encrypt-files
```

> **Note**: Encryption requires Godot 4+ PCK format (version >= 2). Use `--set-godot-version 4.0.0` or higher when creating new encrypted PCK files.

### 📦 Extracting from Embedded PCK ()

```bash
# Extract from self-contained executable (embedded PCK)
godotpcktool game.exe -a e -o extracted

# The tool automatically detects embedded PCK in executables
# Works with both .exe (Windows) and other executable formats
```

### 🔑 Bruteforce Encryption Key ()

```bash
# Search for encryption key in game executable
godotpcktool encrypted.pck -a bruteforce --exe game.exe

# Short form
godotpcktool encrypted.pck -a bf --exe game.exe

# Specify scan range (useful for large executables)
godotpcktool encrypted.pck -a bf --exe game.exe --start-address 0x1000 --end-address 0x100000

# Specify number of threads (default: CPU cores)
godotpcktool encrypted.pck -a bf --exe game.exe --threads 8
```

> **Note**: The bruteforcer scans the executable file byte-by-byte looking for valid 32-byte AES-256 keys. This can take a long time for large files. Progress is reported in real-time with ETA.

### 📦 Embedded PCK Operations ()

#### Rip - Extract Embedded PCK

```bash
# Extract embedded PCK from executable to standalone file
godotpcktool game.exe -a rip -o game.pck

# With encryption key (if PCK is encrypted)
godotpcktool game.exe -a rip -o game.pck --encryption-key YOUR_64_HEX_CHAR_KEY
```

#### Merge - Embed PCK into Executable

```bash
# Merge standalone PCK into executable
godotpcktool game.pck -a merge --exe game.exe

# With encryption key (if PCK is encrypted)
godotpcktool game.pck -a merge --exe game.exe --encryption-key YOUR_64_HEX_CHAR_KEY
```

> **Note**: The merge operation appends the PCK data to the end of the executable and writes a trailer for detection.

#### Remove - Remove Embedded PCK

```bash
# Remove embedded PCK from executable (keeps only the EXE)
godotpcktool game.exe -a remove

# With encryption key (if PCK is encrypted)
godotpcktool game.exe -a remove --encryption-key YOUR_64_HEX_CHAR_KEY
```

#### Split - Separate EXE and PCK

```bash
# Split embedded executable into separate EXE and PCK files
godotpcktool game.exe -a split -o output_game.exe

# The PCK will be saved as output_game.pck automatically
# With encryption key (if PCK is encrypted)
godotpcktool game.exe -a split -o output_game.exe --encryption-key YOUR_64_HEX_CHAR_KEY
```

> **Note**: Split creates two files: the clean executable and the standalone PCK file. The PCK filename is derived from the output path by changing the extension.

### 🔄 Change PCK Version ()

```bash
# Change PCK from Godot 3 to Godot 4 (in-place)
godotpcktool game.pck -a change-version --set-godot-version 4.0.0

# Short form
godotpcktool game.pck -a cv --set-godot-version 4.0.0

# Change version and save to new file
godotpcktool game.pck -a cv --set-godot-version 4.4.0 -o game_new.pck

# With encryption key (if PCK is encrypted)
godotpcktool game.pck -a cv --set-godot-version 4.0.0 --encryption-key YOUR_64_HEX_CHAR_KEY
```

> **Note**: The change-version operation safely rewrites the PCK file to handle all version-specific offset rules correctly. Format version is automatically determined: Godot 3.x → v1, Godot 4.0-4.4 → v2, Godot 4.5+ → v3.

### 🔧 Patch/Overlay (Create Mod PCK)

```bash
# Create a patched PCK by overlaying mod files onto a base game PCK
godotpcktool -a patch --base-pck game.pck -f mod_files/ -o patched_game.pck

# With prefix stripping (remove "mod_files" from paths)
godotpcktool -a patch --base-pck game.pck -f mod_files/ -o patched.pck --remove-prefix mod_files

# Add path prefix to mod files (e.g., put mods under res://mods/)
godotpcktool -a patch --base-pck game.pck -f mod_files/ -o patched.pck --path-prefix mods/

# With encryption key (if base PCK is encrypted)
godotpcktool -a patch --base-pck game.pck -f mod_files/ -o patched.pck --encryption-key YOUR_KEY
```

> **Note**: The patch operation loads the base PCK, then overlays files from the patch directory. Files with the same path will replace the originals. New files are added to the PCK.

### Adding Content

```bash
# Add files with prefix removal
godotpcktool game.pck -a a extracted --remove-prefix extracted

# Long form
godotpcktool --pack game.pck --action add --file extracted --remove-prefix extracted

# Create new pck with specific Godot version
godotpcktool new.pck -a a files/ --remove-prefix files --set-godot-version 4.2.0
```

### Repacking

```bash
# Repack entire pck (useful after modifications)
godotpcktool game.pck -a r
```

## 🎯 Filters

Filter files by various criteria:

### Size Filters

```bash
# Minimum size (exclude files < 1000 bytes)
godotpcktool game.pck --min-size-filter 1000

# Maximum size (exclude files > 1MB)
godotpcktool game.pck --max-size-filter 1048576

# Exact size
godotpcktool game.pck --min-size-filter 1000 --max-size-filter 1000
```

### Name Filters (Regex)

```bash
# Include only .png files
godotpcktool game.pck -i '\.png$'

# Exclude .import files
godotpcktool game.pck -e '\.import$'

# Combine filters
godotpcktool game.pck -i '\.png$' -e 'thumbnail'

# Override filter (include .txt regardless of size filter)
godotpcktool game.pck --min-size-filter 1000 --include-override-filter '\.txt$'
```

## 📋 JSON Bulk Operations

For precise control over file paths in the pck:

### Create a commands file (`commands.json`):

```json
[
  {
    "file": "/absolute/path/to/file.png",
    "target": "textures/file.png"
  },
  {
    "file": "relative/path/script.gd",
    "target": "scripts/script.gd"
  }
]
```

### Run with command file:

```bash
godotpcktool game.pck -a a --command-file commands.json
```

### Stdin mode (for scripting):

```bash
echo '[{"file":"test.txt","target":"data/test.txt"}]' | godotpcktool game.pck -a a -
```

> **Note**: The `target` field should NOT include the `res://` prefix - it will be added automatically.

## 🔧 All Options

| Option                      | Short | Description                                                                   |
| --------------------------- | ----- | ----------------------------------------------------------------------------- |
| `--pack`                    | `-p`  | Path to .pck file                                                             |
| `--action`                  | `-a`  | Action: `list`/`l`, `extract`/`e`, `add`/`a`, `repack`/`r`, `bruteforce`/`bf` |
| `--output`                  | `-o`  | Output directory for extraction                                               |
| `--file`                    | `-f`  | Files to add (comma-separated or multiple flags)                              |
| `--encryption-key`          | `-k`  | **🔐 Decryption key (64 hex chars) for reading encrypted PCK**                |
| `--encrypt-key`             | `-K`  | **🔐 Encryption key (64 hex chars) for creating encrypted PCK**               |
| `--encrypt-index`           |       | **🔐 Encrypt the file index when creating PCK**                               |
| `--encrypt-files`           |       | **🔐 Encrypt file contents when creating PCK**                                |
| `--remove-prefix`           |       | Prefix to remove from file paths                                              |
| `--command-file`            |       | JSON file with bulk commands                                                  |
| `--set-godot-version`       |       | Set Godot version for new pck (e.g., `4.2.0`)                                 |
| `--min-size-filter`         |       | Minimum file size filter                                                      |
| `--max-size-filter`         |       | Maximum file size filter                                                      |
| `--include-regex-filter`    | `-i`  | Include files matching regex                                                  |
| `--exclude-regex-filter`    | `-e`  | Exclude files matching regex                                                  |
| `--include-override-filter` |       | Override other filters for matching files                                     |
| `--exe`                     |       | **🔑 Executable file to scan for encryption key (bruteforce)**                |
| `--start-address`           |       | **🔑 Start address for bruteforce scan (default: 0)**                         |
| `--end-address`             |       | **🔑 End address for bruteforce scan (default: file size)**                   |
| `--threads`                 |       | **🔑 Number of threads for bruteforce (default: CPU cores)**                  |
| `--print-hashes`            |       | Print MD5 hashes in list output                                               |
| `--quieter`                 | `-q`  | Reduce output verbosity                                                       |
| `--version`                 | `-v`  | Show version                                                                  |
| `--help`                    | `-h`  | Show help                                                                     |

## 🏗️ Building

### Requirements

- Rust 1.70+ (install via [rustup](https://rustup.rs/))

### Build Commands

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Format code
cargo fmt

# Lint
cargo clippy
```

### Cross-compilation

```bash
# Windows (from Linux)
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu

# Linux musl (static binary)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## 📁 Project Structure

```
GodotPckTool/
├── Cargo.toml          # Workspace manifest
├── cli/                # CLI application
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
├── pck/                # Core library
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs       # PCK read/parse logic
│       ├── write.rs     # PCK write logic
│       ├── crypto/      # 🔐 Encryption module
│       │   ├── mod.rs   # AES-256-CFB encryption/decryption
│       │   └── block.rs # Block cipher operations
│       └── bruteforce.rs # 🔑 Key bruteforcer
├── Dockerfile
└── README.md
```

## ⚠️ Limitations

- **Sparse bundles**: Warning displayed, may not work correctly

## 🔐 Encryption Technical Details

| Property    | Value                              |
| ----------- | ---------------------------------- |
| Algorithm   | AES-256-CFB                        |
| Key Size    | 256 bits (32 bytes / 64 hex chars) |
| Block Size  | 16 bytes                           |
| Header Size | 40 bytes (MD5 + size + IV)         |

**Encrypted block structure:**

```
[16 bytes MD5] [8 bytes original_size] [16 bytes IV] [encrypted data...]
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file.
