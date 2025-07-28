# /home/chane/tif_crypto_hook/noheader_encrypt_tif.py

"""
noheader_encrypt_tif.py - 对整个 TIFF 文件进行异或加密（包括 TIFF Header）

用法：
    python3 noheader_encrypt_tif.py 原图像路径

    python3 noheader_encrypt_tif.py ./1-6级tif文件/Level_2.tif

输出：
    输出文件名格式为：noheader_changed_原文件名.tif
"""

"""
使用 hexdump 查看加密前后文件内容，是否按 XOR_KEY = 0xFF 加密：
    hexdump -C ./1-6级tif文件/Level_2.tif | head -n 2
    hexdump -C ./1-6级tif文件/noheader_changed_Level_2.tif | head -n 2
"""

import os
import sys

XOR_KEY = 0xFF  # 异或密钥

def encrypt_tif_file(input_path):
    # 检查文件是否存在
    if not os.path.isfile(input_path):
        print(f"[错误] 文件不存在: {input_path}")
        return

    # 获取文件名和路径
    dir_name = os.path.dirname(input_path)
    file_name = os.path.basename(input_path)
    output_path = os.path.join(dir_name, f"noheader_changed_{file_name}")

    # 提示信息
    print(f"[+] 正在加密: {input_path}")
    print(f"[+] 输出路径: {output_path}")

    try:
        # 读取原始文件
        with open(input_path, "rb") as f:
            data = bytearray(f.read())

        # 对整个文件内容进行异或加密
        for i in range(len(data)):
            data[i] ^= XOR_KEY

        # 写入加密后文件
        with open(output_path, "wb") as f:
            f.write(data)

        print("[+] 加密完成 ✅")

    except Exception as e:
        print(f"[错误] 处理文件时出错: {e}")
        return

def main():
    if len(sys.argv) != 2:
        print(f"[使用说明] python3 {sys.argv[0]} 原图像路径")
        print(f"示例: python3 {sys.argv[0]} Level_2.tif")
        sys.exit(1)

    input_path = sys.argv[1].strip()
    encrypt_tif_file(input_path)

if __name__ == "__main__":
    main()