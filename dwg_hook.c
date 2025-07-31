// 文件路径: /home/chane/tif_crypto_hook/dwg_hook.c
// 功能: 通过 LD_PRELOAD 拦截 pread64，对特定加密的 .dwg 文件进行透明解密（0xFF 异或）
// 适用场景: 中望CAD (ZWCAD) 读取被加密的 DWG 文件（文件名包含 "changed_" 且以 ".dwg" 结尾）

// 编译: gcc -shared -fPIC -o libdwg_hook.so dwg_hook.c -ldl -lpthread
// gcc -shared -fPIC -o libdwg_hook.so dwg_hook.c -ldl

// 使用方法（挂载到中望CAD 启动脚本）
// sudo vim /opt/apps/zwcad2025/ZWCADRUN.sh
// 注释掉./ZWCAD "$@" /product ZWCAD
// 添加：LD_PRELOAD=/home/chane/tif_crypto_hook/libdwg_hook.so ./ZWCAD "$@" /product ZWCAD

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <limits.h>
#include <pthread.h>

// ==================== 配置与全局变量 ====================

// 最大可跟踪的文件描述符数量
#define MAX_TRACKED_FD 1024

// 存储文件描述符 (fd) 到文件路径的映射
static char *fd_paths[MAX_TRACKED_FD] = {0};

// 保护 fd_paths 数组的互斥锁（线程安全）
static pthread_mutex_t fd_mutex = PTHREAD_MUTEX_INITIALIZER;

// ==================== 工具函数 ====================

/**
 * 判断给定路径是否为需要解密的目标 DWG 文件
 * 条件:
 *   1. 路径包含子串 "changed_"
 *   2. 路径以 ".dwg" 结尾（不区分大小写）
 * @param path: 文件路径字符串
 * @return: 1 表示是目标文件，0 表示不是
 */
int is_target_dwg_file(const char *path) {
    if (!path) return 0;

    size_t len = strlen(path);
    // 检查是否以 .dwg 结尾（忽略大小写）
    if (len < 4) return 0;
    const char *ext = path + len - 4;
    if (strcasecmp(ext, ".dwg") != 0) return 0;

    // 检查是否包含 "changed_"
    return strstr(path, "changed_") != NULL;
}

/**
 * 记录文件描述符与路径的映射关系
 * 使用 realpath 获取绝对路径，避免相对路径歧义
 * 如果 realpath 失败，则使用 strdup 备份原始路径
 * @param fd: 文件描述符
 * @param path: 文件路径
 */
static void track_fd(int fd, const char *path) {
    if (fd < 0 || fd >= MAX_TRACKED_FD || !path) return;

    pthread_mutex_lock(&fd_mutex);

    // 释放旧路径内存
    free(fd_paths[fd]);
    fd_paths[fd] = NULL;

    // 尝试获取绝对路径
    char *resolved = realpath(path, NULL);
    if (resolved) {
        fd_paths[fd] = resolved;
    } else {
        // realpath 失败（如文件已删除），使用原始路径的副本
        fd_paths[fd] = strdup(path);
        // 注意：strdup 失败时 fd_paths[fd] 为 NULL，在读取时会尝试 /proc/self/fd 回退
    }

    pthread_mutex_unlock(&fd_mutex);
}

// ==================== Hook 函数 ====================

/**
 * 拦截 openat 系统调用
 * 记录新打开文件的 fd 与路径映射
 * 正确处理可变参数（特别是 O_CREAT 时的 mode 参数）
 */
int openat(int dirfd, const char *pathname, int flags, ...) {
    static int (*real_openat)(int, const char *, int, ...) = NULL;
    if (!real_openat) {
        real_openat = dlsym(RTLD_NEXT, "openat");
        if (!real_openat) {
            // 理论上不应发生，但防止崩溃
            fprintf(stderr, "dlsym failed for openat\n");
            return -1;
        }
    }

    mode_t mode = 0;
    // 仅当 flags 包含 O_CREAT 时才需要读取 mode 参数
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    int fd;
    // 根据是否需要 mode 调用真实函数
    if (flags & O_CREAT) {
        fd = real_openat(dirfd, pathname, flags, mode);
    } else {
        fd = real_openat(dirfd, pathname, flags);
    }

    // 成功打开后记录 fd -> path 映射
    if (fd >= 0) {
        track_fd(fd, pathname);
    }

    return fd;
}

/**
 * 拦截 open 系统调用（补充 openat，提高兼容性）
 * 避免因程序使用 open 而非 openat 导致路径未被记录
 */
int open(const char *pathname, int flags, ...) {
    static int (*real_open)(const char *, int, ...) = NULL;
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
        if (!real_open) {
            fprintf(stderr, "dlsym failed for open\n");
            return -1;
        }
    }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    int fd;
    if (flags & O_CREAT) {
        fd = real_open(pathname, flags, mode);
    } else {
        fd = real_open(pathname, flags);
    }

    if (fd >= 0) {
        track_fd(fd, pathname);
    }

    return fd;
}

/**
 * 核心函数：拦截 pread64 系统调用
 * 读取数据后，如果文件是目标加密 DWG 文件，则对缓冲区数据进行 0xFF 异或解密
 */
ssize_t pread64(int fd, void *buf, size_t count, off_t offset) {
    static ssize_t (*real_pread64)(int, void *, size_t, off_t) = NULL;
    if (!real_pread64) {
        real_pread64 = dlsym(RTLD_NEXT, "pread64");
        if (!real_pread64) {
            fprintf(stderr, "dlsym failed for pread64\n");
            return -1;
        }
    }

    // 调用原始 pread64 读取数据
    ssize_t ret = real_pread64(fd, buf, count, offset);

    // 检查返回值和 fd 范围
    if (ret <= 0 || fd < 0 || fd >= MAX_TRACKED_FD) {
        return ret;
    }

    const char *path = NULL;

    // 优先从 fd_paths 获取路径（已通过 open/openat 记录）
    pthread_mutex_lock(&fd_mutex);
    path = fd_paths[fd];
    pthread_mutex_unlock(&fd_mutex);

    // 如果 fd_paths 中没有记录（如通过 dup 或其他方式获得的 fd），尝试从 /proc/self/fd 获取
    if (!path) {
        char procpath[64];
        snprintf(procpath, sizeof(procpath), "/proc/self/fd/%d", fd);
        char real_path[PATH_MAX];
        ssize_t n = readlink(procpath, real_path, sizeof(real_path) - 1);
        if (n != -1) {
            real_path[n] = '\0';
            path = real_path;
        } else {
            // readlink 失败（如 fd 无效），放弃解密
            return ret;
        }
    }

    // 判断是否为需要解密的目标文件
    if (is_target_dwg_file(path)) {
        unsigned char *data = (unsigned char *)buf;
        for (ssize_t i = 0; i < ret; ++i) {
            data[i] ^= 0xFF; // 0xFF 异或解密
        }
    }

    return ret;
}

/**
 * 拦截 close 系统调用
 * 关闭文件时清理 fd_paths 中的记录，防止内存泄漏
 */
int close(int fd) {
    static int (*real_close)(int) = NULL;
    if (!real_close) {
        real_close = dlsym(RTLD_NEXT, "close");
        if (!real_close) {
            fprintf(stderr, "dlsym failed for close\n");
            return -1;
        }
    }

    // 清理资源
    if (fd >= 0 && fd < MAX_TRACKED_FD) {
        pthread_mutex_lock(&fd_mutex);
        free(fd_paths[fd]);
        fd_paths[fd] = NULL;
        pthread_mutex_unlock(&fd_mutex);
    }

    return real_close(fd);
}