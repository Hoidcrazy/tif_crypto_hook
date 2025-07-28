// // /home/chane/tif_crypto_hook/noheader_tif_interceptor.c
// // 编译共享库命令：gcc -Wall -fPIC -shared -o libnoheader_tif_interceptor.so noheader_tif_interceptor.c -ldl
// // 运行查看器（记得加 LD_PRELOAD）
// // LD_PRELOAD=/home/chane/tif_crypto_hook/libnoheader_tif_interceptor.so /usr/bin/kylin-photo-viewer /home/chane/tif_crypto_hook/1-6级tif文件/noheader_changed_Level_2.tif


// #define _GNU_SOURCE
// #include <dlfcn.h>
// #include <unistd.h>
// #include <sys/mman.h>
// #include <fcntl.h>
// #include <string.h>
// #include <stdio.h>
// #include <stdlib.h>

// // 定义加密/解密密钥（与加密脚本一致）
// #define XOR_KEY 0xFF

// // TIFF 文件前8字节的头部大小（魔术数字）
// #define HEADER_SIZE 8

// // 保存文件是否需要解密的标志（每个线程使用一个独立的标记）
// static __thread int is_target_fd[1024];

// // 原始函数指针
// static ssize_t (*real_read)(int, void *, size_t) = NULL;
// static ssize_t (*real_pread64)(int, void *, size_t, off_t) = NULL;
// static void *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;

// // 判断文件是否为加密的 TIFF 文件
// static int check_and_mark_fd(int fd) {
//     char path[256] = {0};
//     char resolved[512] = {0};
//     snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
//     ssize_t len = readlink(path, resolved, sizeof(resolved) - 1);
//     if (len > 0) {
//         resolved[len] = '\0';
//         if (strstr(resolved, "noheader_changed_")) {
//             is_target_fd[fd] = 1;
//             return 1;
//         }
//     }
//     return 0;
// }

// // 解密函数：基于 XOR 0xFF
// static void xor_decrypt(char *buf, size_t size) {
//     for (size_t i = 0; i < size; ++i) {
//         buf[i] ^= XOR_KEY;
//     }
// }

// ssize_t read(int fd, void *buf, size_t count) {
//     if (!real_read)
//         real_read = dlsym(RTLD_NEXT, "read");

//     ssize_t ret = real_read(fd, buf, count);
//     if (ret > 0 && (is_target_fd[fd] || check_and_mark_fd(fd))) {
//         xor_decrypt((char *)buf, ret);
//     }
//     return ret;
// }

// ssize_t pread64(int fd, void *buf, size_t count, off_t offset) {
//     if (!real_pread64)
//         real_pread64 = dlsym(RTLD_NEXT, "pread64");

//     ssize_t ret = real_pread64(fd, buf, count, offset);
//     if (ret > 0 && (is_target_fd[fd] || check_and_mark_fd(fd))) {
//         xor_decrypt((char *)buf, ret);
//     }
//     return ret;
// }

// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
//     if (!real_mmap)
//         real_mmap = dlsym(RTLD_NEXT, "mmap");

//     void *mapped = real_mmap(addr, length, prot, flags, fd, offset);
//     if (mapped != MAP_FAILED && (is_target_fd[fd] || check_and_mark_fd(fd))) {
//         if (prot & PROT_READ && prot & PROT_WRITE) {
//             xor_decrypt((char *)mapped, length);
//         }
//     }
//     return mapped;
// }



// gcc -Wall -fPIC -shared -o libnoheader_tif_interceptor.so noheader_tif_interceptor.c -ldl -D_POSIX_C_SOURCE=200809L
// LD_PRELOAD=/home/chane/tif_crypto_hook/libnoheader_tif_interceptor.so /usr/bin/kylin-photo-viewer /home/chane/tif_crypto_hook/1-6级tif文件/noheader_changed_Level_2.tif
#define _GNU_SOURCE

#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <linux/limits.h>

// 函数指针类型定义
typedef void* (*mmap_func_t)(void*, size_t, int, int, int, off_t);

// 全局变量：原始 mmap 函数
static mmap_func_t real_mmap = NULL;

// 配置项
#define XOR_KEY 0xFF
#define DEBUG_LOG(...) do { fprintf(stderr, "[DEBUG] "); fprintf(stderr, __VA_ARGS__); } while(0)

// 判断是否为加密文件（通过文件名匹配）
static int is_encrypted_tif(const char *path) {
    return path && strstr(path, "noheader_changed_");
}

// 通过 fd 获取文件路径
static int get_file_path(int fd, char *buf, size_t size) {
    char proc_path[PATH_MAX];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(proc_path, buf, size - 1);
    if (len == -1) {
        return -1;
    }
    buf[len] = '\0';
    return 0;
}

// 异或解密函数
static void xor_decrypt(char *buf, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        buf[i] ^= XOR_KEY;
    }
}

// mmap 替换函数
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    // 获取原始 mmap 函数
    if (!real_mmap) {
        real_mmap = dlsym(RTLD_NEXT, "mmap");
        if (!real_mmap) {
            fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
            return MAP_FAILED;
        }
    }

    // 获取文件路径
    char path[PATH_MAX] = {0};
    if (get_file_path(fd, path, sizeof(path)) != 0) {
        return real_mmap(addr, length, prot, flags, fd, offset);
    }

    // 调试输出
    DEBUG_LOG("Opening file: %s\n", path);

    // 判断是否为加密文件
    if (is_encrypted_tif(path)) {
        DEBUG_LOG("Hooked mmap for encrypted TIFF file: %s\n", path);

        // 调用原始 mmap 获取加密文件映射
        void *mapped = real_mmap(addr, length, prot, flags, fd, offset);
        if (mapped == MAP_FAILED) {
            perror("Original mmap failed");
            return MAP_FAILED;
        }

        // 创建匿名映射用于解密后的内容
        void *decrypted = mmap(NULL, length, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (decrypted == MAP_FAILED) {
            perror("Anonymous mmap failed");
            return mapped; // 回退到原始映射
        }

        // 复制原始内容并解密
        memcpy(decrypted, mapped, length);
        xor_decrypt(decrypted, length);

        // 调试输出 magic number
        uint16_t *magic = (uint16_t *)decrypted;
        DEBUG_LOG("Decrypted magic number: 0x%04x (期望 0x4949 或 0x4D4D)\n", *magic);

        return decrypted;
    }

    // 非加密文件，直接调用原始 mmap
    return real_mmap(addr, length, prot, flags, fd, offset);
}