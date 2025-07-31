# /home/chane/tif_crypto_hook/encrypt_dwg.py
"""
encrypt_dwg.py - 对 dwg_tests 文件夹下所有 DWG 文件进行异或加密（包括 DWG Header）

用法：
    python3 encrypt_dwg.py

输出：
    输出文件名格式为：changed_原文件名.dwg
"""


import os
import glob

# 定义异或密钥
XOR_KEY = 0xFF

def xor_encrypt_file(file_path, xor_key):
    # 加密后的文件路径
    encrypted_file_path = os.path.join(os.path.dirname(file_path),
                                        'changed_' + os.path.basename(file_path))
    
    with open(file_path, 'rb') as file:
        data = bytearray(file.read())
        
    # 对文件的每一个字节进行异或操作
    for i in range(len(data)):
        data[i] ^= xor_key
    
    # 将加密后的数据写入新的文件
    with open(encrypted_file_path, 'wb') as file:
        file.write(data)

def main():
    folder_path = './dwg_tests'
    # 获取文件夹中所有的.dwg文件
    dwg_files = glob.glob(os.path.join(folder_path, '*.dwg'))
    
    for dwg_file in dwg_files:
        print(f"正在处理文件: {dwg_file}")
        xor_encrypt_file(dwg_file, XOR_KEY)
        print(f"处理完成并保存为: changed_{os.path.basename(dwg_file)}")

if __name__ == '__main__':
    main()