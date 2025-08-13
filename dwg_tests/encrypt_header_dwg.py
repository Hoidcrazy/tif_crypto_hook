# /home/chane/tif_crypto_hook/dwg_tests/encrypt_header_dwg.py
"""
encrypt_header_dwg.py - 对 dwg_tests 文件夹下所有 DWG 文件进行异或加密，并在开头添加 'AC10' 头部

用法：
    python3 dwg_tests/encrypt_header_dwg.py

输出：
    输出文件名格式为：change_header_原文件名.dwg
"""
# hexdump -C dwg_tests/change_header_room.dwg | head -n 1

import os
import glob

# 定义异或密钥
XOR_KEY = 0xFF

# 定义要添加的头部：AC10
HEADER = bytearray([0x41, 0x43, 0x31, 0x30])

def xor_encrypt_file(file_path, xor_key):
    # 修改输出文件名前缀为 change_header_
    encrypted_file_path = os.path.join(
        os.path.dirname(file_path),
        'change_header_' + os.path.basename(file_path)
    )
    
    # 读取原始文件
    with open(file_path, 'rb') as file:
        data = bytearray(file.read())
        
    # 对每个字节进行异或加密
    for i in range(len(data)):
        data[i] ^= xor_key
    
    # 在加密数据前添加头部 AC10
    final_data = HEADER + data

    # 写入新文件
    with open(encrypted_file_path, 'wb') as file:
        file.write(final_data)

    print(f"已加密并添加头部 'AC10'，保存为: {encrypted_file_path}")

def main():
    folder_path = './dwg_tests'
    
    # 检查目录是否存在
    if not os.path.exists(folder_path):
        print(f"错误：目录 '{folder_path}' 不存在！")
        return

    # 获取所有 .dwg 文件
    dwg_files = glob.glob(os.path.join(folder_path, '*.dwg'))
    
    if not dwg_files:
        print(f"警告：在 '{folder_path}' 中未找到 .dwg 文件。")
        return

    # 处理每个文件
    for dwg_file in dwg_files:
        print(f"正在处理文件: {dwg_file}")
        xor_encrypt_file(dwg_file, XOR_KEY)

if __name__ == '__main__':
    main()