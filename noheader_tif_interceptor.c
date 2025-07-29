// /home/chane/tif_crypto_hook/noheader_tif_interceptor.c
// 编译共享库命令：
// gcc -Wall -fPIC -shared -o libnoheader_tif_interceptor.so noheader_tif_interceptor.c -ldl -D_POSIX_C_SOURCE=200809L
// 运行查看器（记得加 LD_PRELOAD）：
// LD_PRELOAD=/home/chane/tif_crypto_hook/libnoheader_tif_interceptor.so /usr/bin/kylin-photo-viewer /home/chane/tif_crypto_hook/tif_tests/noheader_changed_Level_2.tif

#define _GNU_SOURCE  // 启用 GNU 扩展功能（如 dlsym, readlink 等）

#include <dlfcn.h>      // 用于动态加载函数（dlsym）
#include <unistd.h>     // 提供 readlink 等系统调用
#include <sys/mman.h>   // mmap 相关函数和常量
#include <fcntl.h>      // 文件控制（open 等）
#include <string.h>     // 字符串操作（strstr, memcpy）
#include <stdio.h>      // 输入输出（fprintf, perror）
#include <stdlib.h>     // 标准库
#include <stdint.h>     // 固定宽度整数类型（uint16_t）
#include <errno.h>      // 错误码（errno）
#include <linux/limits.h> // PATH_MAX 定义

// 定义 mmap 函数指针类型，便于 Hook
typedef void* (*mmap_func_t)(void*, size_t, int, int, int, off_t);

// 全局变量：保存原始的 mmap 函数地址
static mmap_func_t real_mmap = NULL;

// 配置：解密密钥（XOR 0xFF）
#define XOR_KEY 0xFF

// 调试宏：输出调试信息（仅在启用时生效）
// 使用方式：DEBUG_LOG("文件路径: %s\n", path);
#define DEBUG_LOG(...) do { fprintf(stderr, "[DEBUG] "); fprintf(stderr, __VA_ARGS__); } while(0)

/**
 * 判断文件路径是否为加密的 TIFF 文件
 * @param path 文件路径
 * @return 1 表示是加密文件，0 表示不是
 * 
 * 规则：路径中包含 "noheader_changed_" 字符串即认为是加密文件
 */
static int is_encrypted_tif(const char *path) {
    // 检查路径是否为 NULL 或者是否包含特定字符串
    DEBUG_LOG("检查文件是否为加密 TIFF: %s\n", path);
    // return path && strstr(path, "noheader_changed_");
    int result = strstr(path, "noheader_changed_Level_2.tif") != NULL;
    if (result) {
        DEBUG_LOG("✅ 匹配到加密文件: %s\n", path);
    }
    return result;
}

/**
 * 通过文件描述符（fd）获取文件的完整路径
 * @param fd 文件描述符
 * @param buf 输出缓冲区
 * @param size 缓冲区大小
 * @return 0 成功，-1 失败
 * 
 * 原理：读取 /proc/self/fd/<fd> 的符号链接目标
 */
static int get_file_path(int fd, char *buf, size_t size) {
    char proc_path[PATH_MAX];
    // 构造 /proc/self/fd/<fd> 路径
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    // 读取符号链接指向的实际路径
    ssize_t len = readlink(proc_path, buf, size - 1);
    if (len == -1) {
        return -1; // 读取失败
    }
    buf[len] = '\0'; // 添加字符串结束符
    return 0;
}

/**
 * 对内存中的数据进行异或解密
 * @param buf 数据缓冲区
 * @param size 数据长度
 * 
 * 使用 XOR_KEY（0xFF）对每个字节进行异或操作
 * 同时输出调试信息，便于验证解密是否正确
 */
static void xor_decrypt(char *buf, size_t size) {
    DEBUG_LOG("正在解密 %zu 字节数据，解密前前8字节: %.8s\n", size, buf);
    for (size_t i = 0; i < size; ++i) {
        buf[i] ^= XOR_KEY; // 每个字节与 0xFF 异或
    }
    DEBUG_LOG("解密完成，解密后前8字节: %.8s\n", buf);
}

/**
 * 替换系统原生的 mmap 函数
 * 当程序调用 mmap 时，实际执行的是此函数
 */
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    // 第一次调用 mmap 时，需要获取系统原始 mmap 函数的地址
    if (!real_mmap) {
        // 使用 dlsym 获取下一个定义的 mmap（即系统原始 mmap）
        real_mmap = dlsym(RTLD_NEXT, "mmap");
        if (!real_mmap) {
            // 如果获取失败，打印错误信息并返回 MAP_FAILED
            fprintf(stderr, "错误：无法获取原始 mmap 函数：%s\n", dlerror());
            return MAP_FAILED;
        }
    }

    // 用于保存文件路径的缓冲区
    char path[PATH_MAX] = {0};

    // 尝试通过文件描述符获取文件的完整路径
    if (get_file_path(fd, path, sizeof(path)) != 0) {
        // 如果获取失败，说明不是普通文件，直接调用原始 mmap
        return real_mmap(addr, length, prot, flags, fd, offset);
    }

    // 输出调试信息：当前正在 mmap 哪个文件
    DEBUG_LOG("正在打开文件: %s\n", path);

    // 如果偏移量不为 0，说明不是从文件开头映射（可能是分块加载）
    // 我们只处理从文件开头映射的情况（即文件头）
    if (offset != 0) {
        DEBUG_LOG("非零偏移量 mmap 调用，返回原始映射\n");
        return real_mmap(addr, length, prot, flags, fd, offset);
    }

    // 检查文件路径是否为加密的 TIFF 文件
    if (is_encrypted_tif(path)) {
        DEBUG_LOG("【HOOK 触发】正在处理加密的 TIFF 文件: %s\n", path);

        // 1. 调用原始 mmap 函数将加密的文件映射到内存
        void *mapped = real_mmap(addr, length, prot, flags, fd, offset);
        if (mapped == MAP_FAILED) {
            // 如果原始 mmap 失败，打印错误信息并返回失败
            perror("原始 mmap 调用失败");
            return MAP_FAILED;
        }

        // 2. 创建一块匿名内存映射区域，用于存放解密后的数据
        void *decrypted = mmap(NULL, length, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (decrypted == MAP_FAILED) {
            // 如果匿名映射失败，打印错误信息并返回原始加密数据（降级处理）
            perror("创建匿名映射失败");
            return mapped;
        }

        // 3. 将加密数据从原始映射复制到匿名映射区域
        memcpy(decrypted, mapped, length);

        // 4. 对复制后的数据进行异或解密
        xor_decrypt(decrypted, length);

        // 5. 返回解密后的内存地址
        // 此时应用程序读取的就是解密后的 TIFF 文件头和内容
        DEBUG_LOG("返回解密后的内存地址: %p\n", decrypted);
        return decrypted;
    }

    // 如果不是加密文件，直接调用原始 mmap 函数，不做任何修改
    return real_mmap(addr, length, prot, flags, fd, offset);
}