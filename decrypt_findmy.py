#!/usr/bin/env python3
"""
FindMy 缓存数据解密脚本
基于对 FindMyCrypto.framework 的逆向分析

支持两组缓存文件解密：
1. FMIP 组 (Find My iPhone) - 使用 FMIPDataManager.bplist 密钥
   - SafeLocations.data, Items.data, Devices.data, FamilyMembers.data, ItemGroups.data, Owner.data
2. FMF 组 (Find My Friends) - 使用 FMFDataManager.bplist 密钥
   - FriendCacheData.data

加密流程：
1. ChaCha20-Poly1305 AEAD 对称加密
2. 使用预先存储的对称密钥进行解密
"""

import plistlib
import base64
import json
import datetime
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

class FindMyDecryptor:
    def __init__(self):
        self.fmip_key = None  # FMIP 组密钥
        self.fmf_key = None   # FMF 组密钥
        
    def load_keys_from_file(self, file_path, key_type):
        """从文件加载密钥数据"""
        try:
            print(f"🔍 尝试从文件加载 {key_type} 密钥: {file_path}")
            
            # 尝试读取 plist 文件
            with open(file_path, 'rb') as f:
                plist_data = plistlib.load(f)
                
            print(f"✅ 成功从文件加载 {key_type} 密钥数据")
            return self.load_keys_from_plist(plist_data, key_type)
            
        except FileNotFoundError:
            print(f"❌ 文件不存在: {file_path}")
            return False
        except Exception as e:
            print(f"❌ 文件读取错误: {e}")
            return False
    
    def load_keys_from_input(self, key_type, filename):
        """从用户输入加载密钥数据"""
        try:
            print(f"\n📝 请输入 {filename} 文件的内容:")
            print(f"提示：可以使用 'xxd -p {filename} | tr -d '\\n'' 获取十六进制内容")
            
            hex_input = input("请输入十六进制内容: ").strip()
            
            # 移除空格和换行符
            hex_input = hex_input.replace(' ', '').replace('\n', '')
            
            # 转换为二进制数据
            binary_data = bytes.fromhex(hex_input)
            
            # 解析为 plist
            plist_data = plistlib.loads(binary_data)
            
            print(f"✅ 成功解析用户输入的 {key_type} 数据")
            return self.load_keys_from_plist(plist_data, key_type)
            
        except ValueError as e:
            print(f"❌ 十六进制数据格式错误: {e}")
            return False
        except Exception as e:
            print(f"❌ 数据解析错误: {e}")
            return False
    
    def load_keys_from_plist(self, plist_data, key_type):
        """从 plist 数据加载密钥"""
        try:
            # 获取对称密钥，支持两种格式：
            # 格式1: 直接 base64 字符串
            # 格式2: 嵌套字典结构 {'key': {'data': base64_string}}
            
            symmetric_key_data = plist_data.get('symmetricKey')
            
            if not symmetric_key_data:
                print(f"❌ plist 中缺少 symmetricKey")
                return False
            
            # 检查是否为嵌套结构
            if isinstance(symmetric_key_data, dict):
                # 嵌套格式: symmetricKey -> key -> data
                key_dict = symmetric_key_data.get('key', {})
                if isinstance(key_dict, dict):
                    symmetric_key_b64 = key_dict.get('data')
                    if isinstance(symmetric_key_b64, bytes):
                        # 如果是 bytes 类型，直接使用
                        symmetric_key_bytes = symmetric_key_b64
                    else:
                        # 如果是字符串，解码 base64
                        symmetric_key_bytes = base64.b64decode(symmetric_key_b64)
                else:
                    print(f"❌ 无效的 symmetricKey 结构")
                    return False
            else:
                # 直接格式: 直接是 base64 字符串
                symmetric_key_bytes = base64.b64decode(symmetric_key_data)
            
            print(f"🔑 {key_type} 对称密钥长度: {len(symmetric_key_bytes)} 字节")
            
            if len(symmetric_key_bytes) != 32:
                print(f"❌ {key_type} 对称密钥长度不正确，应为 32 字节")
                return False
            
            # 根据密钥类型保存到不同的属性
            if key_type == "FMIP":
                self.fmip_key = symmetric_key_bytes
            elif key_type == "FMF":
                self.fmf_key = symmetric_key_bytes
            else:
                print(f"❌ 未知的密钥类型: {key_type}")
                return False
                
            print(f"✅ {key_type} 对称密钥加载成功")
            return True
            
        except Exception as e:
            print(f"❌ 密钥加载错误: {e}")
            return False
    

    
    def decrypt_chacha20_poly1305(self, encrypted_data, key_type):
        """使用 ChaCha20-Poly1305 解密数据"""
        try:
            # 解析 encryptedData 结构
            # 前12字节: nonce
            # 中间部分: 密文
            # 后16字节: 认证标签
            
            if len(encrypted_data) < 28:  # 至少需要 nonce + auth_tag
                print("❌ 加密数据长度不足")
                return None
                
            nonce = encrypted_data[:12]
            ciphertext_with_tag = encrypted_data[12:]
            
            print(f"🔍 Nonce: {nonce.hex()}")
            print(f"🔍 密文+标签长度: {len(ciphertext_with_tag)} 字节")
            
            # 根据密钥类型选择对应的密钥
            if key_type == "FMIP":
                symmetric_key = self.fmip_key
            elif key_type == "FMF":
                symmetric_key = self.fmf_key
            else:
                print(f"❌ 未知的密钥类型: {key_type}")
                return None
                
            # 使用对称密钥解密
            if symmetric_key is None:
                print(f"❌ {key_type} 对称密钥未初始化")
                return None
                
            # 创建 ChaCha20Poly1305 解密器
            cipher = ChaCha20Poly1305(symmetric_key)
            
            # 解密数据
            plaintext = cipher.decrypt(nonce, ciphertext_with_tag, None)
            print(f"✅ 解密成功，明文长度: {len(plaintext)} 字节")
            
            return plaintext
            
        except Exception as e:
            print(f"❌ ChaCha20-Poly1305 解密错误: {e}")
            return None
    
    
    def format_plist_data(self, data, indent=0):
        """格式化 plist 数据以便可读"""
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
        """解密缓存文件"""
        try:
            print(f"🔍 开始解密文件: {file_path} (使用 {key_type} 密钥)")
            
            # 读取 plist 文件
            with open(file_path, 'rb') as f:
                plist_data = plistlib.load(f)
                
            print("📋 plist 数据结构:")
            for key, value in plist_data.items():
                if isinstance(value, bytes):
                    print(f"  {key}: {len(value)} 字节")
                else:
                    print(f"  {key}: {value}")
            
            # 提取加密数据
            encrypted_data = plist_data.get('encryptedData')
            
            if not encrypted_data:
                print("❌ 缺少 encryptedData")
                return None
                
            print(f"🔍 encryptedData 长度: {len(encrypted_data)} 字节")
            
            # 解密数据
            plaintext = self.decrypt_chacha20_poly1305(encrypted_data, key_type)
            
            if plaintext:
                print(f"✅ 解密成功!")
                print(f"📝 明文前100字节: {plaintext[:100]}")
                
                # 尝试解析解密后的数据
                try:
                    # 首先检查是否为 plist 格式
                    if plaintext.startswith(b'bplist'):
                        print("📊 解密后的数据是 plist 格式，正在解析...")
                        inner_plist = plistlib.loads(plaintext)
                        print("📋 解密后的 plist 内容:")
                        print(self.format_plist_data(inner_plist))
                        
                        # 保存解密后的数据到文件
                        output_file = f"{file_path}.decrypted.plist"
                        with open(output_file, 'wb') as f:
                            plistlib.dump(inner_plist, f)
                        print(f"💾 解密后的数据已保存到: {output_file}")
                        
                    elif plaintext.startswith(b'{'):
                        # JSON 格式
                        json_data = json.loads(plaintext.decode('utf-8'))
                        print("📊 解析为 JSON 格式:")
                        print(json.dumps(json_data, indent=2, ensure_ascii=False))
                        
                    else:
                        # 其他格式，尝试作为文本显示
                        print("📝 明文内容 (前1000字节):")
                        try:
                            print(plaintext[:1000].decode('utf-8'))
                        except UnicodeDecodeError:
                            print(f"二进制数据: {plaintext[:1000]}")
                        
                        # 保存原始解密数据
                        output_file = f"{file_path}.decrypted.bin"
                        with open(output_file, 'wb') as f:
                            f.write(plaintext)
                        print(f"💾 原始解密数据已保存到: {output_file}")
                        
                except Exception as e:
                    print(f"⚠️  解析解密数据时出错: {e}")
                    print("📝 明文内容 (前1000字节):")
                    print(plaintext[:1000])
                    
                return plaintext
            
            return None
            
        except Exception as e:
            print(f"❌ 解密文件错误: {e}")
            return None

def main():
    """主函数"""
    decryptor = FindMyDecryptor()
    
    print("🔐 FindMy 缓存数据解密工具")
    print("=" * 50)
    
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
    
    # 处理每个密钥组
    for config in key_configs:
        key_type = config["key_type"]
        key_file = config["key_file"]
        cache_files = config["cache_files"]
        
        print(f"\n🔧 处理 {key_type} 组...")
        
        # 检查是否有对应的缓存文件需要解密
        existing_files = [f for f in cache_files if os.path.exists(f)]
        if not existing_files:
            print(f"⚠️  没有找到 {key_type} 组的缓存文件，跳过...")
            continue
            
        print(f"📁 发现 {key_type} 组缓存文件: {existing_files}")
        
        # 尝试从文件加载密钥
        print(f"1️⃣ 尝试从文件加载 {key_type} 密钥...")
        if not decryptor.load_keys_from_file(key_file, key_type):
            print(f"⚠️  {key_type} 密钥文件加载失败，请手动输入密钥数据")
            
            # 从用户输入加载密钥
            print(f"2️⃣ 从用户输入加载 {key_type} 密钥:")
            try:
                if not decryptor.load_keys_from_input(key_type, key_file):
                    print(f"❌ {key_type} 密钥加载失败，跳过该组...")
                    continue
            except KeyboardInterrupt:
                print(f"\n❌ 用户取消输入，跳过 {key_type} 组...")
                continue
            except Exception as e:
                print(f"❌ 输入错误: {e}，跳过 {key_type} 组...")
                continue
        
        # 解密该组的缓存文件
        print(f"3️⃣ 开始解密 {key_type} 组缓存文件...")
        for file_path in existing_files:
            print(f"\n📁 解密文件: {file_path}")
            decryptor.decrypt_cache_file(file_path, key_type)
    
    print("\n🎉 所有文件处理完成！")

if __name__ == "__main__":
    main() 