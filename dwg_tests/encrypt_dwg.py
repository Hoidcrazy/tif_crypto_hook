# /home/chane/tif_crypto_hook/dwg_tests/encrypt_dwg.py
"""
encrypt_dwg.py - 对指定的 DWG 文件进行异或加密（包括 DWG Header）

用法：
    # 加密单个文件
    python3 encrypt_dwg.py /path/to/your/file.dwg

    # eg.
    python3 dwg_tests/encrypt_dwg.py /home/chane/tif_crypto_hook/dwg_tests/room.dwg

输出：
    输出文件名格式为：changed_原文件名.dwg
    例如：changed_room.dwg
"""
# hexdump -C dwg_tests/changed_20211015-渝北铜锣山矿山公园测绘成果图（ck6-13）（1：500）.dwg | head -n 1

import os
import sys

# 定义异或密钥
XOR_KEY = 0xFF


def xor_encrypt_file(file_path, xor_key):
    # 生成输出文件路径
    dir_name = os.path.dirname(file_path)
    base_name = os.path.basename(file_path)
    encrypted_file_path = os.path.join(dir_name, 'changed_' + base_name)

    print(f"正在读取文件: {file_path}")
    with open(file_path, 'rb') as file:
        data = bytearray(file.read())

    # 对每个字节进行异或加密
    for i in range(len(data)):
        data[i] ^= xor_key

    # 写入加密后的文件
    with open(encrypted_file_path, 'wb') as file:
        file.write(data)

    print(f"加密完成，保存为: {encrypted_file_path}")


def main():
    # 检查命令行参数
    if len(sys.argv) != 2:
        print("❌ 错误：请指定一个文件。\n")
        print("用法：")
        print("    python3 encrypt_dwg.py <文件路径>")
        print("示例：")
        print("    python3 encrypt_dwg.py dwg_tests/room.dwg")
        sys.exit(1)

    file_path = sys.argv[1]

    # 检查文件是否存在
    if not os.path.isfile(file_path):
        print(f"❌ 错误：文件不存在 -> {file_path}")
        sys.exit(1)

    # 检查是否是 .dwg 文件（可选）
    if not file_path.lower().endswith('.dwg'):
        print(f"⚠️  警告：文件可能不是 DWG 格式: {file_path}")

    # 执行加密
    xor_encrypt_file(file_path, XOR_KEY)


if __name__ == '__main__':
    main()