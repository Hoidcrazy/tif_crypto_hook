// tif_hook_read_mmap.c
// 这是一个用于处理加密 TIFF 文件的 read、mmap Hook 实现
// 目前用于测试在麒麟照片查看器中解密 TIF 文件
// LD_PRELOAD=/home/chane/tif_crypto_hook/libtif_hook.so /usr/bin/kylin-photo-viewer "/home/chane/tif_crypto_hook/tif_tests/noheader_changed_Level_2.tif"
// gcc -fPIC -shared -o libtif_hook.so tif_hook_read_mmap.c -ldl

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>  // 必须包含
#include <sys/stat.h>
#include <limits.h>

// =============== 配置 ===============
#define XOR_KEY 0xFF  // XOR加密密钥
// ====================================

// 函数指针，用于调用真实的 read 和 mmap
static ssize_t (*real_read)(int fd, void *buf, size_t count) = NULL;
static size_t (*real_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream) = NULL;
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
 * @brief 通过文件描述符获取文件路径
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
        fprintf(stderr, "[HOOK] readlink 失败: %s (fd=%d)\n", strerror(errno), fd);
        return NULL;
    }
    file_path[len] = '\0';

    // 如果路径以 /dev/ 开头（如 /dev/shm），或包含 (deleted)，可能不是真实文件
    // 但我们也尝试匹配
    return strdup(file_path); // 返回副本
}

/**
 * @brief 判断文件路径是否是我们要解密的目标
 * @param path 文件路径
 * @return 是目标返回 1，否则返回 0
 */
int is_target_file(const char *path) {
    if (!path) return 0;
    // 匹配你加密的文件名特征
    return strstr(path, "noheader_changed_") != NULL;
}

// ==================== Hook 函数 ====================

/**
 * @brief Hooked read 函数
 */
ssize_t read(int fd, void *buf, size_t count) {
    // fprintf(stderr, "[DEBUG] read() called on fd=%d, count=%zu\n", fd, count);
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

    // 方法1: 通过文件路径判断（通用）
    file_path = get_file_path_by_fd(fd);
    if (file_path && is_target_file(file_path)) {
        should_decrypt = 1;
        fprintf(stderr, "[HOOK] 拦截 read(fd=%d, count=%zu) from file: %s\n", fd, count, file_path);
    }
    // 方法2: 强制对特定 fd 解密（调试用，基于你的 strace 输出 fd=10）
    else if (fd == 10) {
        should_decrypt = 1;
        fprintf(stderr, "[HOOK] 强制拦截 fd=%d 的 read(count=%zu)，可能为 TIFF 文件\n", fd, count);
    }

    if (should_decrypt) {
        // 记录解密前数据
        fprintf(stderr, "[HOOK] 解密前8字节: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                ((unsigned char*)buf)[0], ((unsigned char*)buf)[1],
                ((unsigned char*)buf)[2], ((unsigned char*)buf)[3],
                ((unsigned char*)buf)[4], ((unsigned char*)buf)[5],
                ((unsigned char*)buf)[6], ((unsigned char*)buf)[7]);

        // 执行解密
        xor_decrypt(buf, result, XOR_KEY);
        // memset(buf, 'X', result); // 测试：把所有读到的数据变成 'X'

        // 记录解密后数据
        fprintf(stderr, "[HOOK] 解密后8字节: %02x %02x %02x %02x %02x %02x %02x %02x\n",
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
 * @brief Hooked fread 函数
 */
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (!real_fread) {
        real_fread = dlsym(RTLD_NEXT, "fread");
        if (!real_fread) {
            fprintf(stderr, "[HOOK] 错误：无法找到真实的 fread！\n");
            return 0;
        }
    }

    size_t result = real_fread(ptr, size, nmemb, stream);
    if (result == 0) return result;

    // 获取文件路径（通过 fileno）
    int fd = fileno(stream);
    char *path = get_file_path_by_fd(fd);
    if (path && is_target_file(path)) {
        fprintf(stderr, "[HOOK] 拦截 fread(size=%zu, nmemb=%zu) from %s\n", size, nmemb, path);
        fprintf(stderr, "[HOOK] fread 前8字节: %02x %02x %02x %02x ...\n",
                ((uint8_t*)ptr)[0], ((uint8_t*)ptr)[1], ((uint8_t*)ptr)[2], ((uint8_t*)ptr)[3]);
        xor_decrypt(ptr, result * size, XOR_KEY);
        fprintf(stderr, "[HOOK] fread 后8字节: %02x %02x %02x %02x ...\n",
                ((uint8_t*)ptr)[0], ((uint8_t*)ptr)[1], ((uint8_t*)ptr)[2], ((uint8_t*)ptr)[3]);
    }
    if (path) free(path);
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

        // 方法1: 通过文件路径判断
        file_path = get_file_path_by_fd(fd);
        if (file_path && is_target_file(file_path)) {
            should_decrypt = 1;
            fprintf(stderr, "[HOOK] 拦截 mmap(fd=%d, offset=%ld, length=%zu) from file: %s\n",
                    fd, offset, length, file_path);
        }
        // 方法2: 强制对 fd=10 解密
        else if (fd == 10) {
            should_decrypt = 1;
            fprintf(stderr, "[HOOK] 强制拦截 fd=%d 的 mmap(length=%zu, offset=%ld)\n", fd, length, offset);
        }

        if (should_decrypt) {
            // 记录映射前数据
            fprintf(stderr, "[HOOK] mmap 映射前8字节: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                    ((unsigned char*)result)[0], ((unsigned char*)result)[1],
                    ((unsigned char*)result)[2], ((unsigned char*)result)[3],
                    ((unsigned char*)result)[4], ((unsigned char*)result)[5],
                    ((unsigned char*)result)[6], ((unsigned char*)result)[7]);

            // 执行解密
            xor_decrypt(result, length, XOR_KEY);

            // 记录解密后数据
            fprintf(stderr, "[HOOK] mmap 解密后8字节: %02x %02x %02x %02x %02x %02x %02x %02x\n",
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
    fprintf(stderr, "[HOOK] libtif_hook.so 已被成功加载！\n");
    fprintf(stderr, "[HOOK] 配置: XOR_KEY=0x%02x\n", XOR_KEY);
}