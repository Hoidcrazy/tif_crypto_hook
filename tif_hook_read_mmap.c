// LD_PRELOAD=/home/chane/tif_crypto_hook/libtif_hook.so /usr/bin/kylin-photo-viewer "/home/chane/tif_crypto_hook/tif_tests/noheader_changed_Level_2.tif"

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <stdint.h>
#include <errno.h>  // 修复 errno 未定义问题

// =============== 配置 ===============
#define XOR_KEY 0xFF  // 你的加密密钥
// ====================================

// 函数指针，用于调用真实的 read 和 mmap
static ssize_t (*real_read)(int fd, void *buf, size_t count) = NULL;
static void* (*real_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset) = NULL;

/**
 * @brief 对缓冲区数据进行 XOR 解密
 * @param buf 数据缓冲区
 * @param len 数据长度
 * @param key XOR 密钥
 */
void xor_decrypt(void *buf, size_t len, uint8_t key) {
    uint8_t *data = (uint8_t *)buf;
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

/**
 * @brief 通过文件描述符获取文件路径（增强健壮性和调试信息）
 * @param fd 文件描述符
 * @return 成功返回路径字符串（需 free），失败返回 NULL
 */
char* get_file_path_by_fd(int fd) {
    char link_path[64];
    char file_path[4096]; // 足够长的路径缓冲区
    ssize_t len;

    // 构造 /proc/self/fd/<fd> 路径
    snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);

    // 读取符号链接
    len = readlink(link_path, file_path, sizeof(file_path) - 1);
    if (len == -1) {
        fprintf(stderr, "[HOOK] readlink 失败: %s (fd=%d, path=%s)\n", strerror(errno), fd, link_path);
        return NULL;
    }
    file_path[len] = '\0';

    // 【调试】打印获取到的路径
    fprintf(stderr, "[HOOK] 获取到 fd=%d 的路径: '%s'\n", fd, file_path);

    return strdup(file_path); // 返回副本
}

/**
 * @brief 判断文件路径是否是我们要解密的目标
 * @param path 文件路径
 * @return 是目标返回 1，否则返回 0
 */
int is_target_file(const char *path) {
    if (!path) return 0;
    // 匹配你加密的文件名特征（更宽松的匹配）
    return (strstr(path, "noheader_changed_") != NULL) ||
           (strstr(path, "Level_") != NULL); // 可以根据需要添加更多特征
}

// ==================== Hook 函数 ====================

/**
 * @brief Hooked read 函数
 */
ssize_t read(int fd, void *buf, size_t count) {
    // 获取真实 read 函数
    if (!real_read) {
        real_read = dlsym(RTLD_NEXT, "read");
        if (!real_read) {
            fprintf(stderr, "[HOOK] 错误：无法找到真实的 read 函数！\n");
            return -1;
        }
    }

    // 调用真实的 read
    ssize_t result = real_read(fd, buf, count);
    if (result <= 0) {
        return result; // 读取失败或 EOF，直接返回
    }

    // ==================== 解密逻辑开始 ====================
    char *file_path = NULL;
    int should_decrypt = 0;

    // 核心：通过文件路径判断是否为目标文件
    file_path = get_file_path_by_fd(fd);
    if (file_path && is_target_file(file_path)) {
        should_decrypt = 1;
        fprintf(stderr, "[HOOK] ✅ 拦截目标文件 read(fd=%d, count=%zu): %s\n", fd, count, file_path);
    }
    // --- 移除了对 fd==10 的强制判断 ---
    // 这个判断不通用，且可能误伤非目标文件（如 XML）
    // else if (fd == 10) { ... }
    // -------------------------------

    if (should_decrypt) {
        // 记录解密前数据（前8字节）
        fprintf(stderr, "[HOOK]     解密前8字节: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                ((unsigned char*)buf)[0], ((unsigned char*)buf)[1],
                ((unsigned char*)buf)[2], ((unsigned char*)buf)[3],
                ((unsigned char*)buf)[4], ((unsigned char*)buf)[5],
                ((unsigned char*)buf)[6], ((unsigned char*)buf)[7]);

        // 执行解密
        xor_decrypt(buf, result, XOR_KEY);

        // 记录解密后数据（前8字节）
        fprintf(stderr, "[HOOK]     解密后8字节: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                ((unsigned char*)buf)[0], ((unsigned char*)buf)[1],
                ((unsigned char*)buf)[2], ((unsigned char*)buf)[3],
                ((unsigned char*)buf)[4], ((unsigned char*)buf)[5],
                ((unsigned char*)buf)[6], ((unsigned char*)buf)[7]);
    }
    // ==================== 解密逻辑结束 ====================

    if (file_path) free(file_path); // 释放路径内存
    return result;
}

/**
 * @brief Hooked mmap 函数
 */
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    // 获取真实 mmap 函数
    if (!real_mmap) {
        real_mmap = dlsym(RTLD_NEXT, "mmap");
        if (!real_mmap) {
            fprintf(stderr, "[HOOK] 错误：无法找到真实的 mmap 函数！\n");
            return MAP_FAILED;
        }
    }

    // 调用真实的 mmap
    void *result = real_mmap(addr, length, prot, flags, fd, offset);
    if (result == MAP_FAILED) {
        return result;
    }

    // ==================== 解密逻辑开始 ====================
    // 只有可读的映射才需要解密
    if (prot & PROT_READ) {
        char *file_path = NULL;
        int should_decrypt = 0;

        // 核心：通过文件路径判断是否为目标文件
        file_path = get_file_path_by_fd(fd);
        if (file_path && is_target_file(file_path)) {
            should_decrypt = 1;
            fprintf(stderr, "[HOOK] ✅ 拦截目标文件 mmap(fd=%d, offset=%ld, length=%zu): %s\n",
                    fd, offset, length, file_path);
        }

        if (should_decrypt) {
            // 记录映射前数据（前8字节）
            fprintf(stderr, "[HOOK]     mmap 映射前8字节: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                    ((unsigned char*)result)[0], ((unsigned char*)result)[1],
                    ((unsigned char*)result)[2], ((unsigned char*)result)[3],
                    ((unsigned char*)result)[4], ((unsigned char*)result)[5],
                    ((unsigned char*)result)[6], ((unsigned char*)result)[7]);

            // 执行解密
            xor_decrypt(result, length, XOR_KEY);

            // 记录解密后数据（前8字节）
            fprintf(stderr, "[HOOK]     mmap 解密后8字节: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                    ((unsigned char*)result)[0], ((unsigned char*)result)[1],
                    ((unsigned char*)result)[2], ((unsigned char*)result)[3],
                    ((unsigned char*)result)[4], ((unsigned char*)result)[5],
                    ((unsigned char*)result)[6], ((unsigned char*)result)[7]);
        }

        if (file_path) free(file_path);
    }
    // ==================== 解密逻辑结束 ====================

    return result;
}

/**
 * @brief so 构造函数：加载时自动执行
 */
__attribute__((constructor))
void so_loaded() {
    fprintf(stderr, "[HOOK] 🚀 libtif_hook.so 已被成功加载！\n");
    fprintf(stderr, "[HOOK] 🛠️  配置: XOR_KEY=0x%02x\n", XOR_KEY);
    fprintf(stderr, "[HOOK] 🔍 注意：仅对包含 'noheader_changed_' 或 'Level_' 的文件进行解密。\n");
}