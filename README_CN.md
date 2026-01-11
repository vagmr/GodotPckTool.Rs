# GodotPckTool.rs 🦀

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**[English](README.md)** | **[中文文档](README_CN.md)**

一个快速、跨平台的 Godot `.pck` 文件解包/打包命令行工具，使用 Rust 重写。

## ✨ 功能特性

### 核心功能

- 📦 **列出** `.pck` 文件内容
- 📤 **解包** `.pck` 文件
- 📥 **添加** 文件到现有或新建的 `.pck` 文件
- 🔄 **重打包** 整个 `.pck` 文件
- 🎯 **过滤** 按大小、名称模式（正则表达式）筛选文件
- 📋 **JSON 批量操作** 支持脚本化

### 🔐 加密支持（）

- **AES-256-CFB 加密/解密** 支持加密的 PCK 文件（Godot 4+）
- **创建加密 PCK** 支持索引加密和/或文件加密
- 同时支持 **加密索引** 和 **加密文件** 的解密
- **流式解密** 内存友好，适合大文件处理
- 加密/解密时自动进行 MD5 完整性校验

### 📦 嵌入式 PCK 支持（）

- **自动检测** 可执行文件中的嵌入式 PCK（自包含游戏）
- 从 `.exe` 或其他可执行格式中提取 PCK 数据
- 同时支持独立 `.pck` 文件和嵌入式 PCK

### 🛤️ 路径兼容性（）

- **`user://`** 路径解包到 `@@user@@/` 目录
- **`.@@removal@@`** 后缀标记已删除的文件
- **Godot 4.4+** 路径格式兼容（`res://` 前缀处理）

### 平台与性能

- 🐧 **跨平台**: Windows、Linux、macOS
- 🚀 **高性能**: 原生 Rust 性能
- 📦 **单文件**: 无需额外依赖

## 📥 安装

### 从 Releases 下载

从 [Releases](https://github.com/vagmr/GodotPckTool/releases) 页面下载最新的二进制文件。

### 从源码编译

```bash
# 克隆仓库
git clone https://github.com/vagmr/GodotPckTool.git
cd GodotPckTool

# 编译 release 版本
cargo build --release

# 二进制文件位于 target/release/godotpcktool(.exe)
```

### 使用 Docker

```bash
# 构建镜像
docker build -t godotpcktool .

# 运行
docker run --rm -v /path/to/files:/data godotpcktool -p /data/game.pck -a list
```

## 🚀 使用方法

查看帮助：

```bash
godotpcktool --help
```

### 列出内容

```bash
# 简写形式（默认操作是 list）
godotpcktool game.pck

# 完整形式
godotpcktool --pack game.pck --action list

# 显示 MD5 哈希值
godotpcktool game.pck --print-hashes
```

### 解包内容

```bash
# 解包到 'extracted' 文件夹
godotpcktool game.pck -a e -o extracted

# 完整形式
godotpcktool --pack game.pck --action extract --output extracted

# 静默模式（减少输出）
godotpcktool game.pck -a e -o extracted -q
```

### 🔐 解包加密 PCK（）

```bash
# 使用解密密钥解包加密的 PCK
godotpcktool encrypted_game.pck -a e -o extracted --encryption-key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# 密钥必须是 64 个十六进制字符（32 字节 / 256 位）
# 这与 Godot 导出设置中使用的密钥相同
```

> **注意**: 加密密钥与 Godot 导出预设中 "加密" → "加密密钥" 配置的密钥相同，应为 64 个十六进制字符的字符串。

### 🔐 创建加密 PCK（）

```bash
# 创建同时加密索引和文件的加密 PCK
godotpcktool encrypted.pck -a a files/ --remove-prefix files \
  --encrypt-key 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --encrypt-index --encrypt-files

# 仅加密文件索引（文件列表隐藏，但文件内容可读）
godotpcktool encrypted.pck -a a files/ --remove-prefix files \
  --encrypt-key YOUR_64_HEX_CHAR_KEY --encrypt-index

# 仅加密文件内容（文件列表可见，但内容加密）
godotpcktool encrypted.pck -a a files/ --remove-prefix files \
  --encrypt-key YOUR_64_HEX_CHAR_KEY --encrypt-files
```

> **注意**: 加密需要 Godot 4+ PCK 格式（版本 >= 2）。创建新的加密 PCK 文件时请使用 `--set-godot-version 4.0.0` 或更高版本。

### 📦 从嵌入式 PCK 解包（）

```bash
# 从自包含可执行文件（嵌入式 PCK）中解包
godotpcktool game.exe -a e -o extracted

# 工具会自动检测可执行文件中的嵌入式 PCK
# 支持 .exe（Windows）和其他可执行格式
```

### 添加内容

```bash
# 添加文件并移除前缀
godotpcktool game.pck -a a extracted --remove-prefix extracted

# 完整形式
godotpcktool --pack game.pck --action add --file extracted --remove-prefix extracted

# 创建新 pck 并指定 Godot 版本
godotpcktool new.pck -a a files/ --remove-prefix files --set-godot-version 4.2.0
```

### 重打包

```bash
# 重打包整个 pck（修改后使用）
godotpcktool game.pck -a r
```

## 🎯 过滤器

按各种条件过滤文件：

### 大小过滤

```bash
# 最小大小（排除 < 1000 字节的文件）
godotpcktool game.pck --min-size-filter 1000

# 最大大小（排除 > 1MB 的文件）
godotpcktool game.pck --max-size-filter 1048576

# 精确大小
godotpcktool game.pck --min-size-filter 1000 --max-size-filter 1000
```

### 名称过滤（正则表达式）

```bash
# 仅包含 .png 文件
godotpcktool game.pck -i '\.png$'

# 排除 .import 文件
godotpcktool game.pck -e '\.import$'

# 组合过滤器
godotpcktool game.pck -i '\.png$' -e 'thumbnail'

# 覆盖过滤器（无论大小过滤如何都包含 .txt）
godotpcktool game.pck --min-size-filter 1000 --include-override-filter '\.txt$'
```

## 📋 JSON 批量操作

精确控制 pck 中的文件路径：

### 创建命令文件 (`commands.json`)：

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

### 使用命令文件运行：

```bash
godotpcktool game.pck -a a --command-file commands.json
```

### 标准输入模式（用于脚本）：

```bash
echo '[{"file":"test.txt","target":"data/test.txt"}]' | godotpcktool game.pck -a a -
```

> **注意**: `target` 字段不应包含 `res://` 前缀 - 会自动添加。

## 🔧 所有选项

| 选项                        | 简写 | 说明                                                     |
| --------------------------- | ---- | -------------------------------------------------------- |
| `--pack`                    | `-p` | .pck 文件路径                                            |
| `--action`                  | `-a` | 操作: `list`/`l`, `extract`/`e`, `add`/`a`, `repack`/`r` |
| `--output`                  | `-o` | 解包输出目录                                             |
| `--file`                    | `-f` | 要添加的文件（逗号分隔或多次指定）                       |
| `--encryption-key`          | `-k` | **🔐 解密密钥（64 个十六进制字符）用于读取加密的 PCK**   |
| `--encrypt-key`             | `-K` | **🔐 加密密钥（64 个十六进制字符）用于创建加密的 PCK**   |
| `--encrypt-index`           |      | **🔐 创建 PCK 时加密文件索引**                           |
| `--encrypt-files`           |      | **🔐 创建 PCK 时加密文件内容**                           |
| `--remove-prefix`           |      | 从文件路径移除的前缀                                     |
| `--command-file`            |      | 批量命令 JSON 文件                                       |
| `--set-godot-version`       |      | 设置新 pck 的 Godot 版本（如 `4.2.0`）                   |
| `--min-size-filter`         |      | 最小文件大小过滤                                         |
| `--max-size-filter`         |      | 最大文件大小过滤                                         |
| `--include-regex-filter`    | `-i` | 包含匹配正则的文件                                       |
| `--exclude-regex-filter`    | `-e` | 排除匹配正则的文件                                       |
| `--include-override-filter` |      | 覆盖其他过滤器                                           |
| `--print-hashes`            |      | 在列表输出中显示 MD5 哈希                                |
| `--quieter`                 | `-q` | 减少输出详细程度                                         |
| `--version`                 | `-v` | 显示版本                                                 |
| `--help`                    | `-h` | 显示帮助                                                 |

## 🏗️ 构建

### 环境要求

- Rust 1.70+（通过 [rustup](https://rustup.rs/) 安装）

### 构建命令

```bash
# Debug 构建
cargo build

# Release 构建（优化）
cargo build --release

# 运行测试
cargo test

# 格式化代码
cargo fmt

# 代码检查
cargo clippy
```

### 交叉编译

```bash
# Windows（从 Linux）
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu

# Linux musl（静态二进制）
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## 📁 项目结构

```
GodotPckTool/
├── Cargo.toml          # Workspace 配置
├── cli/                # CLI 应用
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
├── pck/                # 核心库
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs      # PCK 读取/解析逻辑
│       ├── write.rs    # PCK 写入逻辑
│       └── crypto.rs   # 🔐 AES-256-CFB 加密/解密
├── Dockerfile
└── README.md
```

## ⚠️ 限制

- **稀疏包**: 显示警告，可能无法正常工作

## 🔐 加密技术细节

| 属性     | 值                                    |
| -------- | ------------------------------------- |
| 算法     | AES-256-CFB                           |
| 密钥大小 | 256 位（32 字节 / 64 个十六进制字符） |
| 块大小   | 16 字节                               |
| 头部大小 | 40 字节（MD5 + 大小 + IV）            |

**加密块结构：**

```
[16 字节 MD5] [8 字节 original_size] [16 字节 IV] [加密数据...]
```

## 📄 许可证

MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。
