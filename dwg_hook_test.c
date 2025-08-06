// 文件路径: /home/chane/tif_crypto_hook/dwg_hook_test.c

// 编译命令:
//   gcc -shared -fPIC -o libdwg_hook.so dwg_hook_test.c -ldl -lpthread
//
// 使用方法（挂载到中望CAD启动脚本）:
//   1. 修改启动脚本 sudo vim /opt/apps/zwcad2025/ZWCADRUN.sh
//   2. 注释原启动行: # ./ZWCAD "$@" /product ZWCAD
//   3. 添加新行: LD_PRELOAD=/home/chane/tif_crypto_hook/libdwg_hook.so ./ZWCAD "$@" /product ZWCAD
//
// 调试方法:
//   设置环境变量开启调试日志: export DWG_HOOK_DEBUG=1
//   重定向输出查看日志: LD_PRELOAD=/home/chane/tif_crypto_hook/libdwg_hook.so /opt/apps/zwcad2025/ZWCADRUN.sh

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>  
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <limits.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>   // 布尔类型支持

// ==================== 配置与全局变量 ====================

// 定义最大可跟踪的文件描述符数量
#define MAX_TRACKED_FD 1024

// 全局数组：存储文件描述符 (fd) 到文件路径字符串的映射
static char *fd_paths[MAX_TRACKED_FD] = {0};

// 互斥锁：保护 fd_paths 数组的读写操作
static pthread_mutex_t fd_mutex = PTHREAD_MUTEX_INITIALIZER;

// 调试标志：控制是否输出调试日志
static int debug_enabled = -1;

// 加密文件魔数标识
#define MAGIC_HEADER 0xBECEBEBC
#define INODE_CACHE_SIZE 1024   // inode缓存大小

// 文件头特征识别
static const unsigned char ENCRYPTED_HEADER[4] = {0xBE, 0xCE, 0xBE, 0xBC};

// inode缓存结构
typedef struct {
    ino_t inode;      // 文件inode号
    bool encrypted;   // 是否加密文件
} inode_cache_t;

static inode_cache_t inode_cache[INODE_CACHE_SIZE] = {{0, false}};
static pthread_mutex_t inode_mutex = PTHREAD_MUTEX_INITIALIZER;

// 修改mmap跟踪结构
typedef struct {
    void *addr;
    size_t length;
    int should_decrypt;
    int prot;        // 原始保护权限
    int flags;       // 映射标志
    int fd;          // 文件描述符
    off_t offset;    // 文件偏移
    bool modified;   // 是否被修改
} mmap_region_t;

// 最大跟踪的 mmap 区域数量
#define MAX_MMAP_REGIONS 256
static mmap_region_t mmap_regions[MAX_MMAP_REGIONS] = {0};
static pthread_mutex_t mmap_mutex = PTHREAD_MUTEX_INITIALIZER;

// ==================== 调试函数 ====================

/**
 * 初始化调试标志
 */
void init_debug_flag() {
    if (debug_enabled == -1) {
        const char *env = getenv("DWG_HOOK_DEBUG");
        debug_enabled = (env && strcmp(env, "1") == 0) ? 1 : 0;
    }
}

/**
 * 调试日志输出宏
 */
#define DEBUG_LOG(fmt, ...) \
    do { \
        init_debug_flag(); \
        if (debug_enabled) { \
            FILE *logfp = fopen("/tmp/dwg_hook.log", "a"); \
            if (logfp) { \
                fprintf(logfp, "[DWG透明加解密] " fmt "\n", ##__VA_ARGS__); \
                fclose(logfp); \
            } \
        } \
    } while (0)

// ==================== 工具函数 ====================

/**
 * 判断给定路径是否为需要解密的目标 DWG 文件
 */
int is_target_dwg_file(const char *path) {
    if (!path) {
        DEBUG_LOG("路径为空");
        return 0;
    }

    DEBUG_LOG("检查文件路径: %s", path);

    size_t len = strlen(path);
    if (len < 4) {
        DEBUG_LOG("文件路径过短: %s", path);
        return 0;
    }
    
    const char *ext = path + len - 4;
    if (strcasecmp(ext, ".dwg") != 0) {
        DEBUG_LOG("文件不是.dwg格式: %s", path);
        return 0;
    }

    if (strstr(path, "changed_") == NULL) {
        DEBUG_LOG("文件路径不包含'changed_': %s", path);
        return 0;
    }

    DEBUG_LOG("目标DWG文件已识别: %s", path);
    return 1;
}

/**
 * 通过inode检查文件是否加密
 */
bool is_encrypted_by_inode(int fd) {
    struct stat file_stat;
    if (fstat(fd, &file_stat) != 0) {
        DEBUG_LOG("fstat失败 fd=%d: %s", fd, strerror(errno));
        return false;
    }
    
    ino_t inode = file_stat.st_ino;
    
    // 检查缓存
    pthread_mutex_lock(&inode_mutex);
    for (int i = 0; i < INODE_CACHE_SIZE; i++) {
        if (inode_cache[i].inode == inode) {
            bool result = inode_cache[i].encrypted;
            pthread_mutex_unlock(&inode_mutex);
            DEBUG_LOG("inode缓存命中: inode=%lu, 加密=%d", inode, result);
            return result;
        }
    }
    pthread_mutex_unlock(&inode_mutex);
    
    // 没有缓存，读取文件头判断
    unsigned char header[4];
    ssize_t bytes_read = pread(fd, header, 4, 0);
    if (bytes_read != 4) {
        DEBUG_LOG("文件头读取失败 inode=%lu", inode);
        return false;
    }
    
    bool encrypted = (memcmp(header, ENCRYPTED_HEADER, 4) == 0);
    
    // 更新缓存
    pthread_mutex_lock(&inode_mutex);
    for (int i = 0; i < INODE_CACHE_SIZE; i++) {
        if (inode_cache[i].inode == 0) {
            inode_cache[i].inode = inode;
            inode_cache[i].encrypted = encrypted;
            break;
        }
    }
    pthread_mutex_unlock(&inode_mutex);
    
    DEBUG_LOG("文件特征识别: inode=%lu, 加密=%d", inode, encrypted);
    return encrypted;
}

/**
 * 判断文件是否需要加解密处理
 */
bool needs_crypto_processing(int fd, const char *path) {
    // 优先使用文件头特征识别
    if (fd >= 0 && is_encrypted_by_inode(fd)) {
        return true;
    }
    
    // 次之使用路径匹配
    return is_target_dwg_file(path);
}

/**
 * 记录文件描述符与文件路径的映射关系
 */
static void track_fd(int fd, const char *path) {
    if (fd < 0 || fd >= MAX_TRACKED_FD || !path) return;

    pthread_mutex_lock(&fd_mutex);

    free(fd_paths[fd]);
    fd_paths[fd] = NULL;

    char *resolved = realpath(path, NULL);
    if (resolved) {
        fd_paths[fd] = resolved;
    } else {
        fd_paths[fd] = strdup(path);
    }

    pthread_mutex_unlock(&fd_mutex);
}

/**
 * 获取指定文件描述符对应的文件路径
 */
static const char *get_fd_path(int fd, char *buf, size_t bufsize) {
    const char *path = NULL;

    pthread_mutex_lock(&fd_mutex);
    path = fd_paths[fd];
    pthread_mutex_unlock(&fd_mutex);

    if (path) return path;

    snprintf(buf, bufsize, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(buf, buf, bufsize - 1);
    if (n != -1) {
        buf[n] = '\0';
        return buf;
    }

    return NULL;
}

/**
 * 修改mmap区域跟踪
 */
static void track_mmap_region(void *addr, size_t length, int should_decrypt, 
                             int prot, int flags, int fd, off_t offset) {
    if (!addr || length == 0) return;

    pthread_mutex_lock(&mmap_mutex);

    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == NULL) {
            mmap_regions[i].addr = addr;
            mmap_regions[i].length = length;
            mmap_regions[i].should_decrypt = should_decrypt;
            mmap_regions[i].prot = prot;
            mmap_regions[i].flags = flags;
            mmap_regions[i].fd = fd;
            mmap_regions[i].offset = offset;
            mmap_regions[i].modified = false;
            DEBUG_LOG("[内存映射] 跟踪区域: 地址=%p, 长度=%zu, fd=%d, 权限=0x%x", 
                     addr, length, fd, prot);
            break;
        }
    }

    pthread_mutex_unlock(&mmap_mutex);
}

/**
 * 查找内存映射区域
 */
static mmap_region_t *find_mmap_region(void *addr) {
    pthread_mutex_lock(&mmap_mutex);
    mmap_region_t *result = NULL;
    
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == NULL) continue;
        
        void *reg_start = mmap_regions[i].addr;
        void *reg_end = (char*)reg_start + mmap_regions[i].length;
        
        if (addr >= reg_start && addr < reg_end) {
            result = &mmap_regions[i];
            break;
        }
    }
    
    pthread_mutex_unlock(&mmap_mutex);
    return result;
}

/**
 * 清理 mmap 区域
 */
static void untrack_mmap_region(void *addr) {
    pthread_mutex_lock(&mmap_mutex);
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == addr) {
            DEBUG_LOG("[内存映射] 解除跟踪: 地址=%p, 长度=%zu", addr, mmap_regions[i].length);
            mmap_regions[i].addr = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&mmap_mutex);
}

/**
 * 安全内存解密
 */
static int safe_decrypt_mmap_region(void *addr, size_t length) {
    if (!addr || length == 0) {
        DEBUG_LOG("[内存解密] 无效地址或长度");
        return -1;
    }

    if (mprotect(addr, length, PROT_READ | PROT_WRITE) != 0) {
        DEBUG_LOG("[内存解密] mprotect失败: %s", strerror(errno));
        return -1;
    }

    DEBUG_LOG("[内存解密] 权限修改成功: %p+%zu 可读写", addr, length);

    unsigned char *data = (unsigned char *)addr;
    for (size_t i = 0; i < length; ++i) {
        data[i] ^= 0xFF;
    }

    DEBUG_LOG("[内存解密] 解密完成: %p+%zu (前3字节: %02x %02x %02x ...)",
              addr, length, data[0], data[1], data[2]);

    if (mprotect(addr, length, PROT_READ) != 0) {
        DEBUG_LOG("[内存解密] 恢复权限失败: %s", strerror(errno));
    } else {
        DEBUG_LOG("[内存解密] 权限恢复: %p+%zu -> 只读", addr, length);
    }

    return 0;
}

/**
 * 安全内存加密
 */
static int safe_encrypt_mmap_region(void *addr, size_t length) {
    if (!addr || length == 0) {
        DEBUG_LOG("[内存加密] 无效地址或长度");
        return -1;
    }

    if (mprotect(addr, length, PROT_READ | PROT_WRITE) != 0) {
        DEBUG_LOG("[内存加密] mprotect失败: %s", strerror(errno));
        return -1;
    }

    unsigned char *data = (unsigned char *)addr;
    for (size_t i = 0; i < length; ++i) {
        data[i] ^= 0xFF;
    }

    DEBUG_LOG("[内存加密] 加密完成: %p+%zu (前3字节: %02x %02x %02x ...)",
              addr, length, data[0], data[1], data[2]);

    if (mprotect(addr, length, PROT_READ) != 0) {
        DEBUG_LOG("[内存加密] 恢复权限失败: %s", strerror(errno));
    }

    return 0;
}

// ==================== Hook 函数实现 ====================

/**
 * 拦截 openat 系统调用
 */
int openat(int dirfd, const char *pathname, int flags, ...) {
    static int (*real_openat)(int, const char *, int, ...) = NULL;
    if (!real_openat)
        real_openat = dlsym(RTLD_NEXT, "openat");

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    DEBUG_LOG("openat: 目录fd=%d, 路径='%s', 标志=0x%x%s, 模式=0%o",
        dirfd, pathname ? pathname : "(空)",
        flags,
        (flags & O_CREAT) ? " | O_CREAT" : "",
        mode);

    int fd;
    if (flags & O_CREAT) {
        fd = real_openat(dirfd, pathname, flags, mode);
    } else {
        fd = real_openat(dirfd, pathname, flags);
    }

    if (fd >= 0) {
        track_fd(fd, pathname);

        if (is_target_dwg_file(pathname)) {
            DEBUG_LOG("[跟踪] openat: fd=%d -> '%s' (目标DWG)", fd, pathname);
            
            // 新创建文件写入魔数
            if ((flags & O_CREAT) && (flags & O_WRONLY)) {
                unsigned int magic = MAGIC_HEADER;
                ssize_t written = pwrite(fd, &magic, 4, 0);
                if (written == 4) {
                    DEBUG_LOG("已写入魔数到新文件: %s", pathname);
                }
            }
        } else {
            DEBUG_LOG("openat: fd=%d -> '%s' (非目标)", fd, pathname);
        }
    } else {
        DEBUG_LOG("openat 失败: dirfd=%d, 路径='%s', 错误=%d (%s)",
                  dirfd, pathname ? pathname : "(空)", errno, strerror(errno));
    }

    return fd;
}

/**
 * 拦截 open 系统调用
 */
int open(const char *pathname, int flags, ...) {
    static int (*real_open)(const char *, int, ...) = NULL;
    if (!real_open)
        real_open = dlsym(RTLD_NEXT, "open");

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    DEBUG_LOG("open: 路径='%s', 标志=0x%x%s, 模式=0%o",
        pathname ? pathname : "(空)",
        flags,
        (flags & O_CREAT) ? " | O_CREAT" : "",
        mode);

    int fd;
    if (flags & O_CREAT) {
        fd = real_open(pathname, flags, mode);
    } else {
        fd = real_open(pathname, flags);
    }

    if (fd >= 0) {
        track_fd(fd, pathname);

        if (is_target_dwg_file(pathname)) {
            DEBUG_LOG("[跟踪] open: fd=%d -> '%s' (目标DWG)", fd, pathname);
            
            if ((flags & O_CREAT) && (flags & O_WRONLY)) {
                unsigned int magic = MAGIC_HEADER;
                ssize_t written = pwrite(fd, &magic, 4, 0);
                if (written == 4) {
                    DEBUG_LOG("已写入魔数到新文件: %s", pathname);
                }
            }
        } else {
            DEBUG_LOG("open: fd=%d -> '%s' (非目标)", fd, pathname);
        }
    } else {
        DEBUG_LOG("open 失败: 路径='%s', 错误=%d (%s)",
                  pathname ? pathname : "(空)", errno, strerror(errno));
    }

    return fd;
}

/**
 * 拦截 pread64 系统调用
 */
ssize_t pread64(int fd, void *buf, size_t count, off_t offset) {
    static ssize_t (*real_pread64)(int, void *, size_t, off_t) = NULL;
    if (!real_pread64)
        real_pread64 = dlsym(RTLD_NEXT, "pread64");

    ssize_t ret = real_pread64(fd, buf, count, offset);

    if (ret <= 0 || fd < 0 || fd >= MAX_TRACKED_FD) {
        DEBUG_LOG("pread64 失败或无效fd: fd=%d, 返回值=%zd", fd, ret);
        return ret;
    }

    char path_buf[PATH_MAX];
    const char *path = get_fd_path(fd, path_buf, sizeof(path_buf));

    DEBUG_LOG("pread64(fd=%d, 偏移=%ld, 大小=%zu, 返回值=%zd, 路径=%s)%s",
              fd, (long)offset, count, ret,
              path ? path : "(未知)",
              needs_crypto_processing(fd, path) ? " [已解密]" : "");

    if (needs_crypto_processing(fd, path)) {
        DEBUG_LOG("需要解密的文件: %s", path);
        unsigned char *data = (unsigned char *)buf;

        DEBUG_LOG("解密前: 前3字节: %02x %02x %02x ...",
            data[0], data[1], data[2]);

        for (ssize_t i = 0; i < ret; ++i) {
            data[i] ^= 0xFF;
        }

        DEBUG_LOG("解密后: 前3字节: %02x %02x %02x ...",
            data[0], data[1], data[2]);

        DEBUG_LOG("文件解密完成: %s", path);
    } else {
        DEBUG_LOG("无需解密的文件: %s", path);
    }

    return ret;
}

/**
 * 拦截 read 系统调用
 */
ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real_read)(int, void *, size_t) = NULL;
    if (!real_read)
        real_read = dlsym(RTLD_NEXT, "read");

    ssize_t ret = real_read(fd, buf, count);
    if (ret <= 0 || fd < 0 || fd >= MAX_TRACKED_FD){
        DEBUG_LOG("read 失败或无效fd: fd=%d, 返回值=%zd", fd, ret);
        return ret;
    }

    char path_buf[PATH_MAX];
    const char *path = get_fd_path(fd, path_buf, sizeof(path_buf));

    DEBUG_LOG("read(fd=%d, 大小=%zu, 返回值=%zd, 路径=%s)%s",
              fd, count, ret,
              path ? path : "(未知)",
              needs_crypto_processing(fd, path) ? " [已解密]" : "");

    if (needs_crypto_processing(fd, path)) {
        DEBUG_LOG("需要解密的文件: %s", path);
        unsigned char *data = (unsigned char *)buf;

        DEBUG_LOG("解密前: 前3字节: %02x %02x %02x ...",
            data[0], data[1], data[2]);
        
        for (ssize_t i = 0; i < ret; ++i) {
            data[i] ^= 0xFF;
        }

        DEBUG_LOG("解密后: 前3字节: %02x %02x %02x ...",
            data[0], data[1], data[2]);

        DEBUG_LOG("文件解密完成: %s", path);
    } else {
        DEBUG_LOG("无需解密的文件: %s", path);
    }

    return ret;
}

/**
 * 拦截 mmap 系统调用
 */
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    static void *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
    if (!real_mmap)
        real_mmap = dlsym(RTLD_NEXT, "mmap");

    char path_buf[PATH_MAX] = {0};
    const char *path = NULL;

    if (fd >= 0) {
        path = get_fd_path(fd, path_buf, sizeof(path_buf));
    }

    DEBUG_LOG("mmap: 地址=%p, 长度=%zu, 权限=0x%x, 标志=0x%x, fd=%d, 偏移=%ld, 路径=%s",
              addr, length, prot, flags, fd, (long)offset, path ? path : "(无fd)");

    void *ptr = real_mmap(addr, length, prot, flags, fd, offset);
    if (ptr == MAP_FAILED) {
        DEBUG_LOG("mmap 失败: 错误=%d (%s)", errno, strerror(errno));
        return ptr;
    }

    int should_decrypt = 0;
    if (fd >= 0 && path && needs_crypto_processing(fd, path)) {
        should_decrypt = 1;
        DEBUG_LOG("[内存映射] 目标文件映射: fd=%d, 路径=%s, 区域=%p+%zu", fd, path, ptr, length);
    } else {
        DEBUG_LOG("mmap: 此映射无需解密 (fd=%d)", fd);
    }

    if (should_decrypt) {
        if (safe_decrypt_mmap_region(ptr, length) == 0) {
            DEBUG_LOG("[内存映射解密] 成功解密映射区域: %p+%zu", ptr, length);
        } else {
            DEBUG_LOG("[内存映射解密] 解密映射区域失败: %p+%zu", ptr, length);
        }
    }

    track_mmap_region(ptr, length, should_decrypt, prot, flags, fd, offset);

    return ptr;
}

/**
 * 拦截 mmap64 系统调用
 */
void *mmap64(void *addr, size_t length, int prot, int flags, int fd, off64_t offset) {
    static void *(*real_mmap64)(void *, size_t, int, int, int, off64_t) = NULL;
    if (!real_mmap64)
        real_mmap64 = dlsym(RTLD_NEXT, "mmap64");

    char path_buf[PATH_MAX] = {0};
    const char *path = NULL;

    if (fd >= 0) {
        path = get_fd_path(fd, path_buf, sizeof(path_buf));
    }

    DEBUG_LOG("mmap64: 地址=%p, 长度=%zu, 权限=0x%x, 标志=0x%x, fd=%d, 偏移=%lld, 路径=%s",
              addr, length, prot, flags, fd, (long long)offset, path ? path : "(无fd)");

    void *ptr = real_mmap64(addr, length, prot, flags, fd, offset);
    if (ptr == MAP_FAILED) {
        DEBUG_LOG("mmap64 失败: 错误=%d (%s)", errno, strerror(errno));
        return ptr;
    }

    int should_decrypt = 0;
    if (fd >= 0 && path && needs_crypto_processing(fd, path)) {
        should_decrypt = 1;
        DEBUG_LOG("[内存映射64] 目标文件映射: fd=%d, 路径=%s, 区域=%p+%zu", fd, path, ptr, length);
    } else {
        DEBUG_LOG("mmap64: 此映射无需解密 (fd=%d)", fd);
    }

    if (should_decrypt) {
        if (safe_decrypt_mmap_region(ptr, length) == 0) {
            DEBUG_LOG("[内存映射解密] 成功解密映射区域 (mmap64): %p+%zu", ptr, length);
        } else {
            DEBUG_LOG("[内存映射解密] 解密映射区域失败 (mmap64): %p+%zu", ptr, length);
        }
    }

    track_mmap_region(ptr, length, should_decrypt, prot, flags, fd, offset);

    return ptr;
}

/**
 * munmap Hook：清理 mmap 记录
 */
int munmap(void *addr, size_t length) {
    static int (*real_munmap)(void *, size_t) = NULL;
    if (!real_munmap)
        real_munmap = dlsym(RTLD_NEXT, "munmap");

    DEBUG_LOG("munmap: 地址=%p, 长度=%zu", addr, length);

    mmap_region_t *region = find_mmap_region(addr);
    if (region && region->should_decrypt && region->modified) {
        DEBUG_LOG("munmap: 加密已修改区域 %p+%zu", addr, length);
        safe_encrypt_mmap_region(addr, length);
        
        // 同步到磁盘
        if (region->fd >= 0) {
            msync(addr, length, MS_SYNC);
        }
    }

    int ret = real_munmap(addr, length);
    if (ret == 0) {
        DEBUG_LOG("munmap: 成功解除映射 %p+%zu", addr, length);
        untrack_mmap_region(addr);
    } else {
        DEBUG_LOG("munmap 失败: 地址=%p, 错误=%d (%s)", addr, errno, strerror(errno));
    }

    return ret;
}

// ==================== 写入加密功能 ====================

/**
 * 拦截 write 系统调用
 */
ssize_t write(int fd, const void *buf, size_t count) {
    static ssize_t (*real_write)(int, const void *, size_t) = NULL;
    if (!real_write)
        real_write = dlsym(RTLD_NEXT, "write");

    char path_buf[PATH_MAX] = {0};
    const char *path = get_fd_path(fd, path_buf, sizeof(path_buf));
    int is_target = path && needs_crypto_processing(fd, path);
    
    DEBUG_LOG("write(fd=%d, 大小=%zu, 路径=%s, 目标文件=%d)",
              fd, count, path ? path : "(未知)", is_target);

    if (!is_target || count == 0 || !buf) {
        return real_write(fd, buf, count);
    }

    void *encrypted_buf = malloc(count);
    if (!encrypted_buf) {
        DEBUG_LOG("write: 内存分配失败 大小=%zu", count);
        errno = ENOMEM;
        return -1;
    }

    memcpy(encrypted_buf, buf, count);
    unsigned char *data = (unsigned char *)encrypted_buf;
    for (size_t i = 0; i < count; i++) {
        data[i] ^= 0xFF;
    }

    DEBUG_LOG("加密后写入: 前3字节: %02x %02x %02x ... (原始: %02x %02x %02x ...)",
              data[0], data[1], data[2],
              ((unsigned char *)buf)[0], ((unsigned char *)buf)[1], ((unsigned char *)buf)[2]);

    ssize_t ret = real_write(fd, encrypted_buf, count);
    free(encrypted_buf);

    DEBUG_LOG("write: 返回 %zd %s", ret, ret < 0 ? strerror(errno) : "");
    return ret;
}

/**
 * 拦截 pwrite64 系统调用
 */
ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset) {
    static ssize_t (*real_pwrite64)(int, const void *, size_t, off_t) = NULL;
    if (!real_pwrite64)
        real_pwrite64 = dlsym(RTLD_NEXT, "pwrite64");

    char path_buf[PATH_MAX] = {0};
    const char *path = get_fd_path(fd, path_buf, sizeof(path_buf));
    int is_target = path && needs_crypto_processing(fd, path);
    
    DEBUG_LOG("pwrite64(fd=%d, 偏移=%ld, 大小=%zu, 路径=%s, 目标文件=%d)",
              fd, (long)offset, count, path ? path : "(未知)", is_target);

    if (!is_target || count == 0 || !buf) {
        return real_pwrite64(fd, buf, count, offset);
    }

    void *encrypted_buf = malloc(count);
    if (!encrypted_buf) {
        DEBUG_LOG("pwrite64: 内存分配失败 大小=%zu", count);
        errno = ENOMEM;
        return -1;
    }

    memcpy(encrypted_buf, buf, count);
    unsigned char *data = (unsigned char *)encrypted_buf;
    for (size_t i = 0; i < count; i++) {
        data[i] ^= 0xFF;
    }

    DEBUG_LOG("pwrite64加密: 前3字节: %02x %02x %02x ... (原始: %02x %02x %02x ...)",
              data[0], data[1], data[2],
              ((unsigned char *)buf)[0], ((unsigned char *)buf)[1], ((unsigned char *)buf)[2]);

    ssize_t ret = real_pwrite64(fd, encrypted_buf, count, offset);
    free(encrypted_buf);

    DEBUG_LOG("pwrite64: 返回 %zd %s", ret, ret < 0 ? strerror(errno) : "");
    return ret;
}

/**
 * 拦截 msync 系统调用
 */
int msync(void *addr, size_t length, int flags) {
    static int (*real_msync)(void *, size_t, int) = NULL;
    if (!real_msync)
        real_msync = dlsym(RTLD_NEXT, "msync");

    DEBUG_LOG("msync: 地址=%p, 长度=%zu, 标志=0x%x", addr, length, flags);

    mmap_region_t *region = find_mmap_region(addr);
    int ret = 0;
    
    if (region && region->should_decrypt && region->modified) {
        DEBUG_LOG("msync: 加密已修改区域 %p+%zu", addr, length);
        
        // 加密并同步
        safe_encrypt_mmap_region(addr, length);
        ret = real_msync(addr, length, flags);
        safe_decrypt_mmap_region(addr, length);
        
        region->modified = false;
        DEBUG_LOG("msync: 数据已加密并同步");
    } else {
        ret = real_msync(addr, length, flags);
    }

    DEBUG_LOG("msync: 返回 %d %s", ret, ret < 0 ? strerror(errno) : "");
    return ret;
}

/**
 * 拦截 mprotect 系统调用
 */
int mprotect(void *addr, size_t len, int prot) {
    static int (*real_mprotect)(void *, size_t, int) = NULL;
    if (!real_mprotect)
        real_mprotect = dlsym(RTLD_NEXT, "mprotect");
    
    mmap_region_t *region = find_mmap_region(addr);
    if (region) {
        region->prot = prot;
        if (prot & PROT_WRITE) {
            region->modified = true;
            DEBUG_LOG("标记区域 %p+%zu 为可写", addr, len);
        }
    }
    
    return real_mprotect(addr, len, prot);
}

/**
 * 拦截 rename 系统调用
 */
int rename(const char *oldpath, const char *newpath) {
    static int (*real_rename)(const char *, const char *) = NULL;
    if (!real_rename)
        real_rename = dlsym(RTLD_NEXT, "rename");
    
    DEBUG_LOG("重命名: 原路径='%s', 新路径='%s'", oldpath, newpath);
    
    // 检查源文件是否加密
    int src_fd = open(oldpath, O_RDONLY);
    bool is_encrypted = false;
    if (src_fd >= 0) {
        is_encrypted = is_encrypted_by_inode(src_fd);
        close(src_fd);
    }
    
    int ret = real_rename(oldpath, newpath);
    
    // 更新缓存
    if (ret == 0 && is_encrypted) {
        struct stat file_stat;
        if (stat(newpath, &file_stat) == 0) {
            pthread_mutex_lock(&inode_mutex);
            for (int i = 0; i < INODE_CACHE_SIZE; i++) {
                if (inode_cache[i].inode == file_stat.st_ino) {
                    DEBUG_LOG("更新inode缓存: inode=%lu, 新路径=%s", 
                             file_stat.st_ino, newpath);
                    break;
                }
            }
            pthread_mutex_unlock(&inode_mutex);
        }
    }
    
    return ret;
}

/**
 * 拦截 close 系统调用
 */
int close(int fd) {
    static int (*real_close)(int) = NULL;
    if (!real_close)
        real_close = dlsym(RTLD_NEXT, "close");

    char *tracked_path = NULL;

    pthread_mutex_lock(&fd_mutex);
    if (fd >= 0 && fd < MAX_TRACKED_FD && fd_paths[fd] != NULL) {
        tracked_path = strdup(fd_paths[fd]);
    }
    pthread_mutex_unlock(&fd_mutex);

    DEBUG_LOG("close: fd=%d, 路径='%s'", fd, tracked_path ? tracked_path : "(空)");

    int ret = real_close(fd);

    if (ret == 0) {
        DEBUG_LOG("close: fd=%d 成功关闭", fd);
    } else {
        DEBUG_LOG("close 失败: fd=%d, 错误=%d (%s)", fd, errno, strerror(errno));
    }

    pthread_mutex_lock(&fd_mutex);
    if (fd >= 0 && fd < MAX_TRACKED_FD) {
        free(fd_paths[fd]);
        fd_paths[fd] = NULL;
    }
    pthread_mutex_unlock(&fd_mutex);

    free(tracked_path);

    return ret;
}