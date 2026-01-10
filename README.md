# GodotPckTool.rs 🦀

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A fast, cross-platform CLI tool for unpacking and packing Godot `.pck` files, rewritten in Rust.


## ✨ Features

- 📦 **List** contents of `.pck` files
- 📤 **Extract** files from `.pck` archives
- 📥 **Add** files to existing or new `.pck` files
- 🔄 **Repack** entire `.pck` files
- 🎯 **Filter** files by size, name patterns (regex)
- 📋 **JSON bulk operations** for scripting
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

| Option                      | Short | Description                                                |
| --------------------------- | ----- | ---------------------------------------------------------- |
| `--pack`                    | `-p`  | Path to .pck file                                          |
| `--action`                  | `-a`  | Action: `list`/`l`, `extract`/`e`, `add`/`a`, `repack`/`r` |
| `--output`                  | `-o`  | Output directory for extraction                            |
| `--file`                    | `-f`  | Files to add (comma-separated or multiple flags)           |
| `--remove-prefix`           |       | Prefix to remove from file paths                           |
| `--command-file`            |       | JSON file with bulk commands                               |
| `--set-godot-version`       |       | Set Godot version for new pck (e.g., `4.2.0`)              |
| `--min-size-filter`         |       | Minimum file size filter                                   |
| `--max-size-filter`         |       | Maximum file size filter                                   |
| `--include-regex-filter`    | `-i`  | Include files matching regex                               |
| `--exclude-regex-filter`    | `-e`  | Exclude files matching regex                               |
| `--include-override-filter` |       | Override other filters for matching files                  |
| `--print-hashes`            |       | Print MD5 hashes in list output                            |
| `--quieter`                 | `-q`  | Reduce output verbosity                                    |
| `--version`                 | `-v`  | Show version                                               |
| `--help`                    | `-h`  | Show help                                                  |

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
│       ├── lib.rs      # PCK read/parse logic
│       └── write.rs    # PCK write logic
├── Dockerfile
└── README.md
```

## ⚠️ Limitations

- **Encrypted PCK files**: Detection only - decryption not supported
- **Sparse bundles**: Warning displayed, may not work correctly

## 📄 License

MIT License - see [LICENSE](LICENSE) file.
