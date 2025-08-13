# /home/chane/tif_crypto_hook/encrypt_tif.py
# 编写一个Python脚本，用于异或加密TIF文件并添加原始企业文件头
# 运行脚本：python3 /home/chane/tif_crypto_hook/encrypt_tif.py

import os
import sys

# 原始企业文件头（未加密）
ORIGINAL_HEADER = bytes([
    0xFF, 0xF7, 0xF0, 0x7F, 0x77, 0x70, 0x0F, 0x07, 0x07, 0x0F, 0x70, 0x77, 0x7F, 0xF0, 0xF7, 0xFF,
    0xC4, 0xCF, 0xBE, 0xA9, 0xBC, 0xAA, 0xD3, 0xA1, 0xD0, 0xC5, 0xCF, 0xA2, 0xBF, 0xC6, 0xBC, 0xBC,
    0xD3, 0xD0, 0xCF, 0xDE, 0xB9, 0xAB, 0xCB, 0xBE, 0xBC, 0xD3, 0xC3, 0xDC, 0xCE, 0xC4, 0xBC, 0xFE
] + [0xFF] * (4096 - 48))  # 填充至4096字节

def encrypt_file(input_path, output_path):
    """加密TIF文件并添加原始企业文件头"""
    with open(input_path, 'rb') as f:
        original_data = f.read()
    
    # 加密数据（每个字节异或0xFF）
    encrypted_data = bytes(b ^ 0xFF for b in original_data)
    
    # 写入新文件：原始文件头 + 加密数据
    with open(output_path, 'wb') as f:
        f.write(ORIGINAL_HEADER)
        f.write(encrypted_data)
    print(f"加密完成: {os.path.basename(input_path)} -> {os.path.basename(output_path)}")

if __name__ == "__main__":
    input_dir = "/home/chane/tif_crypto_hook/1-6级tif文件"
    
    # 加密目录下所有TIF文件
    for filename in os.listdir(input_dir):
        if filename.lower().endswith(('.tif', '.tiff')) and not filename.startswith("changed_"):
            input_path = os.path.join(input_dir, filename)
            output_path = os.path.join(input_dir, f"changed_{filename}")
            
            # 如果加密文件不存在，则创建
            if not os.path.exists(output_path):
                encrypt_file(input_path, output_path)
    
    print("所有TIF文件加密完成！")