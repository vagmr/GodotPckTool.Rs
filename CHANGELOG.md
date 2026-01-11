# 更新日志

本项目的所有重要变更都将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

## [v0.2.0] - 2026-01-11

### 新增

- 📦 **嵌入式 PCK 操作**

  - **Rip**: 从可执行文件中提取嵌入的 PCK 到独立文件
  - **Merge**: 将独立 PCK 合并嵌入到可执行文件中
  - **Remove**: 从可执行文件中移除嵌入的 PCK
  - **Split**: 将嵌入式 PCK 分离为独立的 EXE + PCK 文件
  - 支持 Godot 3 和 Godot 4+ 的偏移修复
  - 支持加密 PCK 的嵌入式操作

- 🔄 **版本管理**

  - **Change Version**: 在 Godot 版本之间转换 PCK（3.x ↔ 4.x ↔ 4.4+）
  - 根据 Godot 版本自动调整格式版本（v1/v2/v3）
  - 安全的重写方式正确处理所有偏移规则
  - 支持就地修改或输出到新文件

- 🔧 **补丁/覆盖功能**
  - **Patch**: 基于已有 PCK 创建补丁包（Mod 支持）
  - 将目录中的文件覆盖到基础 PCK 上
  - 支持路径前缀剥离和添加
  - 自动识别替换文件和新增文件

### CLI 新命令

- `godotpcktool game.exe -a rip -o game.pck` - 提取嵌入式 PCK
- `godotpcktool game.pck -a merge --exe game.exe` - 合并 PCK 到可执行文件
- `godotpcktool game.exe -a remove` - 移除嵌入式 PCK
- `godotpcktool game.exe -a split -o output.exe` - 分离 EXE 和 PCK
- `godotpcktool game.pck -a change-version --set-godot-version 4.0.0` - 修改 PCK 版本
- `godotpcktool game.pck -a cv --set-godot-version 4.0.0 -o new.pck` - 修改版本并输出到新文件
- `godotpcktool -a patch --base-pck game.pck -f mod_files/ -o patched.pck` - 创建补丁 PCK

## [v0.1.0] - 2026-01-11

### 新增

- 📦 **核心 PCK 操作**

  - 列出 `.pck` 文件内容，支持显示 MD5 哈希
  - 从 `.pck` 文件中解包文件
  - 向现有或新建的 `.pck` 文件添加文件
  - 重新打包整个 `.pck` 文件

- 🔐 **加密支持**

  - 支持 Godot 4+ PCK 文件的 AES-256-CFB 加密/解密
  - 创建加密 PCK，支持索引加密和/或文件加密
  - 流式解密，内存友好，适合大文件处理
  - MD5 完整性校验

- 🔑 **密钥暴力破解**

  - 从可执行文件中暴力搜索 32 字节 AES-256 加密密钥
  - 多线程并行扫描
  - 实时进度报告，显示预计剩余时间
  - 支持取消操作

- 📦 **嵌入式 PCK 支持**

  - 自动检测可执行文件中的嵌入式 PCK（自包含游戏）
  - 从 `.exe` 或其他可执行格式中提取 PCK 数据

- 🛤️ **路径兼容性**

  - `user://` 路径解包到 `@@user@@/` 目录
  - `.@@removal@@` 后缀标记已删除的文件
  - Godot 4.4+ 路径格式兼容

- 🎯 **过滤功能**

  - 按文件大小过滤（最小/最大）
  - 按名称模式过滤（正则表达式）
  - 支持包含/排除过滤器及覆盖规则

- 📋 **JSON 批量操作**
  - 支持命令文件进行脚本化操作
  - 支持标准输入模式，便于管道集成

### 平台支持

- 🐧 Linux (x86_64)
- 🪟 Windows (x86_64)
- 🍎 macOS (x86_64)
