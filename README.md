# FindMy Cache Decryptor

[![English](https://img.shields.io/badge/Language-English-blue)](#english) [![中文](https://img.shields.io/badge/Language-中文-red)](#中文)

---

## English

### Overview

**FindMy Cache Decryptor** is a reverse-engineered tool designed to decrypt cached data files from Apple's Find My application on macOS. Since macOS 14.4, Apple has implemented encryption for Find My cache data, rendering many existing open-source projects non-functional. This project provides a comprehensive solution through reverse engineering of macOS PrivateFrameworks.

### Features

- ✅ **Full Decryption Support**: Decrypt all Find My cache files (FMIP and FMF groups)
- 🔐 **Advanced Encryption**: Handles ChaCha20-Poly1305 AEAD encryption
- 🔍 **Automatic Detection**: Automatically detects and processes cache files
- 📊 **Data Parsing**: Parses decrypted data into readable formats
- 🛡️ **Security-Focused**: Implements proper cryptographic verification
- 🔧 **Easy to Use**: Simple command-line interface

### Supported Cache Files

#### FMIP Core (Find My iPhone)
- `SafeLocations.data` - Safe location definitions
- `Items.data` - Tracked items information
- `Devices.data` - Device location data
- `FamilyMembers.data` - Family member information
- `ItemGroups.data` - Item grouping data
- `Owner.data` - Account owner information

#### FMF Core (Find My Friends)
- `FriendCacheData.data` - Friends location data

### Installation

1. **Install Python Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Extract Keychain Keys**
   
   Use the [FMIPDataManager-extractor](https://github.com/Pnut-GGG/FMIPDataManager-extractor) project to extract keys from macOS Keychain:
   ```bash
   git clone https://github.com/Pnut-GGG/FMIPDataManager-extractor
   cd FMIPDataManager-extractor
   # Follow the project's instructions to extract keys
   ```

3. **Prepare Key Files**
   
   Save the extracted keys as `FMIPDataManager.bplist` and `FMFDataManager.bplist` in the project directory.

### Usage

1. **Copy Cache Directories**
   ```bash
   # Copy Find My cache directories to project root
   cp -r ~/Library/Caches/com.apple.findmy.fmipcore ./
   cp -r ~/Library/Caches/com.apple.findmy.fmfcore ./
   ```

2. **Run Decryption**
   ```bash
   python3 decrypt_findmy.py
   ```

3. **View Results**
   
   Decrypted files will be saved with `.decrypted.plist` or `.decrypted.bin` extensions.

### Technical Details

#### Reverse Engineering Process

The decryption process was developed through comprehensive reverse engineering:

1. **Application Analysis**: `Find My.app` → `FMIPCore.framework` → `FindMyCrypto.framework`
2. **Algorithm Identification**: ChaCha20-Poly1305 AEAD encryption
3. **Data Structure Analysis**: 
   - Key format: plist with `privateKey` and `symmetricKey`
   - Cache format: plist with `encryptedData` and `signature`
   - Nonce extraction: First 12 bytes of `encryptedData`
   - Authentication tag: Last 16 bytes of `encryptedData`

#### Encryption Scheme

```
encryptedData = nonce(12 bytes) + ciphertext + auth_tag(16 bytes)
```

- **Algorithm**: ChaCha20-Poly1305 AEAD
- **Key Size**: 256-bit symmetric key
- **Nonce Size**: 96-bit (12 bytes)
- **Tag Size**: 128-bit (16 bytes)

### Acknowledgments

Special thanks to the following open-source projects:

- **[beaconstorekey-extractor](https://github.com/pajowu/beaconstorekey-extractor)**: Provided insights for keychain key extraction
- **[dyld-shared-cache-extractor](https://github.com/keith/dyld-shared-cache-extractor)**: Enabled extraction of macOS PrivateFrameworks
- **[ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)**: Significantly accelerated reverse engineering analysis

### License

This project is for educational and research purposes only. Please ensure compliance with local laws and Apple's terms of service.

### Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

---

## 中文

### 概述

**FindMy Cache Decryptor** 是一个用于解密 macOS 上 Apple Find My 应用程序缓存数据文件的逆向工程工具。自 macOS 14.4 以来，Apple 对 Find My 缓存数据实施了加密，导致许多现有的开源项目无法正常工作。本项目通过对 macOS PrivateFrameworks 的逆向分析提供了完整的解决方案。

### 功能特性

- ✅ **完整解密支持**: 解密所有 Find My 缓存文件（FMIP 和 FMF 组）
- 🔐 **高级加密**: 处理 ChaCha20-Poly1305 AEAD 加密
- 🔍 **自动检测**: 自动检测并处理缓存文件
- 📊 **数据解析**: 将解密数据解析为可读格式
- 🛡️ **安全专注**: 实施适当的加密验证
- 🔧 **易于使用**: 简单的命令行界面

### 支持的缓存文件

#### FMIP Core (查找我的 iPhone)
- `SafeLocations.data` - 安全位置定义
- `Items.data` - 追踪物品信息
- `Devices.data` - 设备位置数据
- `FamilyMembers.data` - 家庭成员信息
- `ItemGroups.data` - 物品分组数据
- `Owner.data` - 账户所有者信息

#### FMF Core (查找我的朋友)
- `FriendCacheData.data` - 朋友位置数据

### 安装

1. **安装 Python 依赖**
   ```bash
   pip install -r requirements.txt
   ```

2. **提取钥匙串密钥**
   
   使用 [FMIPDataManager-extractor](https://github.com/Pnut-GGG/FMIPDataManager-extractor) 项目从 macOS 钥匙串中提取密钥：
   ```bash
   git clone https://github.com/Pnut-GGG/FMIPDataManager-extractor
   cd FMIPDataManager-extractor
   # 按照项目说明提取密钥
   ```

3. **准备密钥文件**
   
   将提取的密钥保存为项目目录中的 `FMIPDataManager.bplist` 和 `FMFDataManager.bplist` 文件。

### 使用方法

1. **复制缓存目录**
   ```bash
   # 将 Find My 缓存目录复制到项目根目录
   cp -r ~/Library/Caches/com.apple.findmy.fmipcore ./
   cp -r ~/Library/Caches/com.apple.findmy.fmfcore ./
   ```

2. **运行解密**
   ```bash
   python3 decrypt_findmy.py
   ```

3. **查看结果**
   
   解密文件将以 `.decrypted.plist` 或 `.decrypted.bin` 扩展名保存。

### 技术细节

#### 逆向工程过程

解密过程通过全面的逆向工程开发：

1. **应用程序分析**: `Find My.app` → `FMIPCore.framework` → `FindMyCrypto.framework`
2. **算法识别**: ChaCha20-Poly1305 AEAD 加密
3. **数据结构分析**: 
   - 密钥格式: 包含 `privateKey` 和 `symmetricKey` 的 plist
   - 缓存格式: 包含 `encryptedData` 和 `signature` 的 plist
   - Nonce 提取: `encryptedData` 的前 12 字节
   - 认证标签: `encryptedData` 的后 16 字节

#### 加密方案

```
encryptedData = nonce(12 字节) + 密文 + 认证标签(16 字节)
```

- **算法**: ChaCha20-Poly1305 AEAD
- **密钥大小**: 256 位对称密钥
- **Nonce 大小**: 96 位（12 字节）
- **标签大小**: 128 位（16 字节）

### 致谢

特别感谢以下开源项目：

- **[beaconstorekey-extractor](https://github.com/pajowu/beaconstorekey-extractor)**: 为钥匙串密钥提取提供了见解
- **[dyld-shared-cache-extractor](https://github.com/keith/dyld-shared-cache-extractor)**: 实现了 macOS PrivateFrameworks 的提取
- **[ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)**: 显著加速了逆向工程分析

### 许可证

本项目仅用于教育和研究目的。请确保遵守当地法律和 Apple 的服务条款。

### 贡献

欢迎贡献！请随时提交问题和拉取请求。 