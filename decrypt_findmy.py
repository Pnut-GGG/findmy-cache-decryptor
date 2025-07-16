#!/usr/bin/env python3
"""
FindMy Cache Data Decryption Script
FindMy 缓存数据解密脚本
Based on reverse engineering analysis of FindMyCrypto.framework
基于对 FindMyCrypto.framework 的逆向分析

Supports decryption of two cache file groups:
支持两组缓存文件解密：
1. FMIP Group (Find My iPhone) - uses FMIPDataManager.bplist key
1. FMIP 组 (Find My iPhone) - 使用 FMIPDataManager.bplist 密钥
   - SafeLocations.data, Items.data, Devices.data, FamilyMembers.data, ItemGroups.data, Owner.data
   - SafeLocations.data, Items.data, Devices.data, FamilyMembers.data, ItemGroups.data, Owner.data
2. FMF Group (Find My Friends) - uses FMFDataManager.bplist key
2. FMF 组 (Find My Friends) - 使用 FMFDataManager.bplist 密钥
   - FriendCacheData.data
   - FriendCacheData.data

Encryption Process:
加密流程：
1. ChaCha20-Poly1305 AEAD symmetric encryption
1. ChaCha20-Poly1305 AEAD 对称加密
2. Uses pre-stored symmetric key for decryption
2. 使用预先存储的对称密钥进行解密
"""

import plistlib
import base64
import json
import datetime
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

class FindMyDecryptor:
    """
    FindMy Cache Data Decryptor Class
    FindMy 缓存数据解密器类
    Handles decryption of FindMy cache files using ChaCha20-Poly1305 encryption
    使用 ChaCha20-Poly1305 加密处理 FindMy 缓存文件解密
    """
    
    def __init__(self):
        """
        Initialize the decryptor with empty keys
        初始化解密器，设置空密钥
        """
        self.fmip_key = None  # FMIP group key / FMIP 组密钥
        self.fmf_key = None   # FMF group key / FMF 组密钥
        
    def load_keys_from_file(self, file_path, key_type):
        """
        Load key data from file
        从文件加载密钥数据
        
        Args:
            file_path (str): Path to the key file
            key_type (str): Type of key ('FMIP' or 'FMF')
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Try to load key from file
            print(f"🔍 尝试从文件加载 {key_type} 密钥: {file_path}")
            
            # Try to read plist file
            # 尝试读取 plist 文件
            with open(file_path, 'rb') as f:
                plist_data = plistlib.load(f)
                
            # Successfully loaded key data from file
            print(f"✅ 成功从文件加载 {key_type} 密钥数据")
            return self.load_keys_from_plist(plist_data, key_type)
            
        except FileNotFoundError:
            # File not found error
            print(f"❌ 文件不存在: {file_path}")
            return False
        except Exception as e:
            # File reading error
            print(f"❌ 文件读取错误: {e}")
            return False
    
    def load_keys_from_input(self, key_type, filename):
        """
        Load key data from user input
        从用户输入加载密钥数据
        
        Args:
            key_type (str): Type of key ('FMIP' or 'FMF')
            filename (str): Name of the key file for reference
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Prompt user for file contents
            print(f"\n📝 请输入 {filename} 文件的内容:")
            # Hint: you can use 'xxd -p filename | tr -d '\\n'' to get hex content
            print(f"提示：可以使用 'xxd -p {filename} | tr -d '\\n'' 获取十六进制内容")
            
            hex_input = input("请输入十六进制内容: ").strip()
            
            # Remove spaces and newlines
            # 移除空格和换行符
            hex_input = hex_input.replace(' ', '').replace('\n', '')
            
            # Convert to binary data
            # 转换为二进制数据
            binary_data = bytes.fromhex(hex_input)
            
            # Parse as plist
            # 解析为 plist
            plist_data = plistlib.loads(binary_data)
            
            # Successfully parsed user input data
            print(f"✅ 成功解析用户输入的 {key_type} 数据")
            return self.load_keys_from_plist(plist_data, key_type)
            
        except ValueError as e:
            # Hexadecimal data format error
            print(f"❌ 十六进制数据格式错误: {e}")
            return False
        except Exception as e:
            # Data parsing error
            print(f"❌ 数据解析错误: {e}")
            return False
    
    def load_keys_from_plist(self, plist_data, key_type):
        """
        Load keys from plist data
        从 plist 数据加载密钥
        
        Args:
            plist_data (dict): Parsed plist data
            key_type (str): Type of key ('FMIP' or 'FMF')
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get symmetric key, supports two formats:
            # 获取对称密钥，支持两种格式：
            # Format 1: Direct base64 string
            # 格式1: 直接 base64 字符串
            # Format 2: Nested dictionary structure {'key': {'data': base64_string}}
            # 格式2: 嵌套字典结构 {'key': {'data': base64_string}}
            
            symmetric_key_data = plist_data.get('symmetricKey')
            
            if not symmetric_key_data:
                # Missing symmetricKey in plist
                print(f"❌ plist 中缺少 symmetricKey")
                return False
            
            # Check if it's a nested structure
            # 检查是否为嵌套结构
            if isinstance(symmetric_key_data, dict):
                # Nested format: symmetricKey -> key -> data
                # 嵌套格式: symmetricKey -> key -> data
                key_dict = symmetric_key_data.get('key', {})
                if isinstance(key_dict, dict):
                    symmetric_key_b64 = key_dict.get('data')
                    if isinstance(symmetric_key_b64, bytes):
                        # If it's bytes type, use directly
                        # 如果是 bytes 类型，直接使用
                        symmetric_key_bytes = symmetric_key_b64
                    else:
                        # If it's string, decode base64
                        # 如果是字符串，解码 base64
                        symmetric_key_bytes = base64.b64decode(symmetric_key_b64)
                else:
                    # Invalid symmetricKey structure
                    print(f"❌ 无效的 symmetricKey 结构")
                    return False
            else:
                # Direct format: directly base64 string
                # 直接格式: 直接是 base64 字符串
                symmetric_key_bytes = base64.b64decode(symmetric_key_data)
            
            # Print symmetric key length
            print(f"🔑 {key_type} 对称密钥长度: {len(symmetric_key_bytes)} 字节")
            
            if len(symmetric_key_bytes) != 32:
                # Incorrect symmetric key length, should be 32 bytes
                print(f"❌ {key_type} 对称密钥长度不正确，应为 32 字节")
                return False
            
            # Save to different attributes based on key type
            # 根据密钥类型保存到不同的属性
            if key_type == "FMIP":
                self.fmip_key = symmetric_key_bytes
            elif key_type == "FMF":
                self.fmf_key = symmetric_key_bytes
            else:
                # Unknown key type
                print(f"❌ 未知的密钥类型: {key_type}")
                return False
                
            # Symmetric key loaded successfully
            print(f"✅ {key_type} 对称密钥加载成功")
            return True
            
        except Exception as e:
            # Key loading error
            print(f"❌ 密钥加载错误: {e}")
            return False
    
    def decrypt_chacha20_poly1305(self, encrypted_data, key_type):
        """
        Decrypt data using ChaCha20-Poly1305
        使用 ChaCha20-Poly1305 解密数据
        
        Args:
            encrypted_data (bytes): Encrypted data to decrypt
            key_type (str): Type of key to use ('FMIP' or 'FMF')
            
        Returns:
            bytes: Decrypted plaintext data, or None if failed
        """
        try:
            # Parse encryptedData structure
            # 解析 encryptedData 结构
            # First 12 bytes: nonce
            # 前12字节: nonce
            # Middle part: ciphertext
            # 中间部分: 密文
            # Last 16 bytes: authentication tag
            # 后16字节: 认证标签
            
            if len(encrypted_data) < 28:  # At least need nonce + auth_tag
                # Insufficient encrypted data length
                print("❌ 加密数据长度不足")
                return None
                
            nonce = encrypted_data[:12]
            ciphertext_with_tag = encrypted_data[12:]
            
            print(f"🔍 Nonce: {nonce.hex()}")
            # Ciphertext + tag length
            print(f"🔍 密文+标签长度: {len(ciphertext_with_tag)} 字节")
            
            # Select corresponding key based on key type
            # 根据密钥类型选择对应的密钥
            if key_type == "FMIP":
                symmetric_key = self.fmip_key
            elif key_type == "FMF":
                symmetric_key = self.fmf_key
            else:
                # Unknown key type
                print(f"❌ 未知的密钥类型: {key_type}")
                return None
                
            # Decrypt using symmetric key
            # 使用对称密钥解密
            if symmetric_key is None:
                # Symmetric key not initialized
                print(f"❌ {key_type} 对称密钥未初始化")
                return None
                
            # Create ChaCha20Poly1305 decryptor
            # 创建 ChaCha20Poly1305 解密器
            cipher = ChaCha20Poly1305(symmetric_key)
            
            # Decrypt data
            # 解密数据
            plaintext = cipher.decrypt(nonce, ciphertext_with_tag, None)
            # Decryption successful, plaintext length
            print(f"✅ 解密成功，明文长度: {len(plaintext)} 字节")
            
            return plaintext
            
        except Exception as e:
            # ChaCha20-Poly1305 decryption error
            print(f"❌ ChaCha20-Poly1305 解密错误: {e}")
            return None
    
    def format_plist_data(self, data, indent=0):
        """
        Format plist data for readability
        格式化 plist 数据以便可读
        
        Args:
            data: Data to format
            indent (int): Indentation level
            
        Returns:
            str: Formatted string representation
        """
        spaces = "  " * indent
        
        if isinstance(data, dict):
            result = "{\n"
            for key, value in data.items():
                result += f"{spaces}  {key}: {self.format_plist_data(value, indent + 1)}\n"
            result += f"{spaces}}}"
            return result
        elif isinstance(data, list):
            result = "[\n"
            for item in data:
                result += f"{spaces}  {self.format_plist_data(item, indent + 1)}\n"
            result += f"{spaces}]"
            return result
        elif isinstance(data, bytes):
            return f"<{len(data)} bytes: {data[:20].hex()}{'...' if len(data) > 20 else ''}>"
        elif isinstance(data, datetime.datetime):
            return f"<datetime: {data.isoformat()}>"
        else:
            return str(data)
    
    def decrypt_cache_file(self, file_path, key_type):
        """
        Decrypt cache file
        解密缓存文件
        
        Args:
            file_path (str): Path to the cache file to decrypt
            key_type (str): Type of key to use ('FMIP' or 'FMF')
            
        Returns:
            bytes: Decrypted data, or None if failed
        """
        try:
            # Start decrypting file
            print(f"🔍 开始解密文件: {file_path} (使用 {key_type} 密钥)")
            
            # Read plist file
            # 读取 plist 文件
            with open(file_path, 'rb') as f:
                plist_data = plistlib.load(f)
                
            # Print plist data structure
            print("📋 plist 数据结构:")
            for key, value in plist_data.items():
                if isinstance(value, bytes):
                    print(f"  {key}: {len(value)} 字节")
                else:
                    print(f"  {key}: {value}")
            
            # Extract encrypted data
            # 提取加密数据
            encrypted_data = plist_data.get('encryptedData')
            
            if not encrypted_data:
                # Missing encryptedData
                print("❌ 缺少 encryptedData")
                return None
                
            # Print encryptedData length
            print(f"🔍 encryptedData 长度: {len(encrypted_data)} 字节")
            
            # Decrypt data
            # 解密数据
            plaintext = self.decrypt_chacha20_poly1305(encrypted_data, key_type)
            
            if plaintext:
                # Decryption successful!
                print(f"✅ 解密成功!")
                # First 100 bytes of plaintext
                print(f"📝 明文前100字节: {plaintext[:100]}")
                
                # Try to parse decrypted data
                # 尝试解析解密后的数据
                try:
                    # First check if it's plist format
                    # 首先检查是否为 plist 格式
                    if plaintext.startswith(b'bplist'):
                        # Decrypted data is plist format, parsing...
                        print("📊 解密后的数据是 plist 格式，正在解析...")
                        inner_plist = plistlib.loads(plaintext)
                        # Content of decrypted plist
                        print("📋 解密后的 plist 内容:")
                        print(self.format_plist_data(inner_plist))
                        
                        # Save decrypted data to file
                        # 保存解密后的数据到文件
                        output_file = f"{file_path}.decrypted.plist"
                        with open(output_file, 'wb') as f:
                            plistlib.dump(inner_plist, f)
                        # Decrypted data saved to
                        print(f"💾 解密后的数据已保存到: {output_file}")
                        
                    elif plaintext.startswith(b'{'):
                        # JSON format
                        # JSON 格式
                        json_data = json.loads(plaintext.decode('utf-8'))
                        # Parsed as JSON format
                        print("📊 解析为 JSON 格式:")
                        print(json.dumps(json_data, indent=2, ensure_ascii=False))
                        
                    else:
                        # Other formats, try to display as text
                        # 其他格式，尝试作为文本显示
                        # Plaintext content (first 1000 bytes)
                        print("📝 明文内容 (前1000字节):")
                        try:
                            print(plaintext[:1000].decode('utf-8'))
                        except UnicodeDecodeError:
                            # Binary data
                            print(f"二进制数据: {plaintext[:1000]}")
                        
                        # Save raw decrypted data
                        # 保存原始解密数据
                        output_file = f"{file_path}.decrypted.bin"
                        with open(output_file, 'wb') as f:
                            f.write(plaintext)
                        # Raw decrypted data saved to
                        print(f"💾 原始解密数据已保存到: {output_file}")
                        
                except Exception as e:
                    # Error occurred while parsing decrypted data
                    print(f"⚠️  解析解密数据时出错: {e}")
                    # Plaintext content (first 1000 bytes)
                    print("📝 明文内容 (前1000字节):")
                    print(plaintext[:1000])
                    
                return plaintext
            
            return None
            
        except Exception as e:
            # File decryption error
            print(f"❌ 解密文件错误: {e}")
            return None

def main():
    """
    Main function
    主函数
    """
    decryptor = FindMyDecryptor()
    
    # FindMy Cache Data Decryption Tool
    print("🔐 FindMy 缓存数据解密工具")
    print("=" * 50)
    
    # Define key files and corresponding cache files
    # 定义密钥文件和对应的缓存文件
    key_configs = [
        {
            "key_type": "FMIP",
            "key_file": "FMIPDataManager.bplist",
            "cache_files": [
                'com.apple.findmy.fmipcore/SafeLocations.data',
                'com.apple.findmy.fmipcore/Items.data', 
                'com.apple.findmy.fmipcore/Devices.data',
                'com.apple.findmy.fmipcore/FamilyMembers.data',
                'com.apple.findmy.fmipcore/ItemGroups.data',
                'com.apple.findmy.fmipcore/Owner.data'
            ]
        },
        {
            "key_type": "FMF",
            "key_file": "FMFDataManager.bplist",
            "cache_files": [
                'com.apple.findmy.fmfcore/FriendCacheData.data'
            ]
        }
    ]
    
    # Process each key group
    # 处理每个密钥组
    for config in key_configs:
        key_type = config["key_type"]
        key_file = config["key_file"]
        cache_files = config["cache_files"]
        
        # Processing key group
        print(f"\n🔧 处理 {key_type} 组...")
        
        # Check if there are corresponding cache files to decrypt
        # 检查是否有对应的缓存文件需要解密
        existing_files = [f for f in cache_files if os.path.exists(f)]
        if not existing_files:
            # No cache files found for group, skipping...
            print(f"⚠️  没有找到 {key_type} 组的缓存文件，跳过...")
            continue
            
        # Found cache files for group
        print(f"📁 发现 {key_type} 组缓存文件: {existing_files}")
        
        # Try to load key from file
        # 尝试从文件加载密钥
        print(f"1️⃣ 尝试从文件加载 {key_type} 密钥...")
        if not decryptor.load_keys_from_file(key_file, key_type):
            # Key file loading failed, please manually input key data
            print(f"⚠️  {key_type} 密钥文件加载失败，请手动输入密钥数据")
            
            # Load key from user input
            # 从用户输入加载密钥
            print(f"2️⃣ 从用户输入加载 {key_type} 密钥:")
            try:
                if not decryptor.load_keys_from_input(key_type, key_file):
                    # Key loading failed, skipping this group...
                    print(f"❌ {key_type} 密钥加载失败，跳过该组...")
                    continue
            except KeyboardInterrupt:
                # User cancelled input, skipping group...
                print(f"\n❌ 用户取消输入，跳过 {key_type} 组...")
                continue
            except Exception as e:
                # Input error, skipping group...
                print(f"❌ 输入错误: {e}，跳过 {key_type} 组...")
                continue
        
        # Decrypt cache files for this group
        # 解密该组的缓存文件
        print(f"3️⃣ 开始解密 {key_type} 组缓存文件...")
        for file_path in existing_files:
            # Decrypt file
            print(f"\n📁 解密文件: {file_path}")
            decryptor.decrypt_cache_file(file_path, key_type)
    
    # All files processed!
    print("\n🎉 所有文件处理完成！")

if __name__ == "__main__":
    main() 