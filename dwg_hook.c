// 文件路径: /home/chane/tif_crypto_hook/dwg_hook.c

// 编译命令:
//   gcc -shared -fPIC -o libdwg_hook.so dwg_hook.c -ldl -lpthread
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
#include <stdbool.h>
#include <stdint.h>

// ==================== 配置与全局变量 ====================

// 定义最大可跟踪的文件描述符数量
#define MAX_TRACKED_FD 1024

// 文件信息类型
#define CRYPT_INFO_FILE 1
#define CRYPT_INFO_MAP 2
#define CRYPT_INFO_ADDRESS 3

// 文件上下文信息结构
typedef struct {
    int type;                    // 记录类型
    int fd;                      // 文件描述符
    char *file_path;             // 文件路径
    bool is_target_dwg;          // 是否为目标 DWG 文件
    bool is_synchronize;         // 是否同步
    bool is_buffering;           // 是否有缓冲
    bool is_created;             // 是否为新建句柄
    bool is_decrypt_when_close;  // 是否需要在关闭后解密
    bool is_encrypt_when_close;  // 是否需要在关闭后加密
    
    // 文件统计信息
    struct stat file_stat;       // 文件状态信息
    off_t current_offset;        // 当前文件偏移
    
    // 引用计数（用于处理 dup 等情况）
    int ref_count;
} fd_context_t;

// mmap 区域信息结构
typedef struct {
    int type;                    // 记录类型 CRYPT_INFO_MAP/ADDRESS
    void *addr;                  // 映射地址
    size_t length;               // 映射长度
    int fd;                      // 关联的文件描述符
    off_t offset;                // 文件偏移
    int prot;                    // 保护权限
    int flags;                   // 映射标志
    
    // 加密状态
    bool should_decrypt;         // 是否需要解密
    bool in_memory_encrypted;    // 内存中是否为加密状态
    bool disk_encrypted;         // 磁盘上是否为加密状态
    bool modified;               // 是否被修改
    
    // 关联的文件上下文
    fd_context_t *fd_ctx;        // 指向对应的文件上下文
} mmap_context_t;

// FD 字典：存储文件描述符到上下文的映射
static fd_context_t *fd_contexts[MAX_TRACKED_FD] = {0};
static pthread_mutex_t fd_dict_mutex = PTHREAD_MUTEX_INITIALIZER;

// mmap 区域字典
#define MAX_MMAP_REGIONS 256
static mmap_context_t mmap_contexts[MAX_MMAP_REGIONS] = {0};
static pthread_mutex_t mmap_dict_mutex = PTHREAD_MUTEX_INITIALIZER;

// 调试标志：控制是否输出调试日志
static int debug_enabled = -1;

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

// ==================== FD 字典管理函数 ====================

/**
 * 判断给定路径是否为需要解密的目标 DWG 文件
 */
static bool is_target_dwg_file(const char *path) {
    if (!path) {
        return false;
    }

    size_t len = strlen(path);
    if (len < 4) {
        return false;
    }
    
    const char *ext = path + len - 4;
    if (strcasecmp(ext, ".dwg") != 0) {
        return false;
    }

    // 检查是否包含 "changed_" 或者是完整路径匹配
    if (strstr(path, "changed_") != NULL) {
        return true;
    }
    
    // 检查是否为指定的测试文件
    if (strstr(path, "/home/chane/tif_crypto_hook/dwg_tests/changed_room.dwg") != NULL) {
        return true;
    }

    return false;
}

/**
 * 创建文件上下文
 */
static fd_context_t *create_fd_context(int fd, const char *path, int flags) {
    if (fd < 0 || fd >= MAX_TRACKED_FD || !path) {
        return NULL;
    }

    fd_context_t *ctx = malloc(sizeof(fd_context_t));
    if (!ctx) {
        DEBUG_LOG("创建 FD 上下文失败: 内存不足");
        return NULL;
    }

    memset(ctx, 0, sizeof(fd_context_t));
    
    ctx->type = CRYPT_INFO_FILE;
    ctx->fd = fd;
    ctx->file_path = strdup(path);
    ctx->is_target_dwg = is_target_dwg_file(path);
    ctx->is_created = (flags & O_CREAT) != 0;
    ctx->ref_count = 1;
    
    // 获取文件状态信息
    if (fstat(fd, &ctx->file_stat) == 0) {
        DEBUG_LOG("FD上下文: fd=%d, 路径=%s, 大小=%ld, 目标文件=%d", 
                  fd, path, (long)ctx->file_stat.st_size, ctx->is_target_dwg);
    } else {
        DEBUG_LOG("FD上下文: fd=%d, 路径=%s, fstat失败: %s", 
                  fd, path, strerror(errno));
    }

    return ctx;
}

/**
 * 销毁文件上下文
 */
static void destroy_fd_context(fd_context_t *ctx) {
    if (!ctx) return;
    
    free(ctx->file_path);
    free(ctx);
}

/**
 * 添加 FD 到字典
 */
static fd_context_t *add_fd_to_dict(int fd, const char *path, int flags) {
    if (fd < 0 || fd >= MAX_TRACKED_FD) {
        return NULL;
    }

    pthread_mutex_lock(&fd_dict_mutex);
    
    // 如果已存在，先清理
    if (fd_contexts[fd]) {
        fd_contexts[fd]->ref_count--;
        if (fd_contexts[fd]->ref_count <= 0) {
            destroy_fd_context(fd_contexts[fd]);
        }
        fd_contexts[fd] = NULL;
    }
    
    // 创建新的上下文
    fd_context_t *ctx = create_fd_context(fd, path, flags);
    if (ctx) {
        fd_contexts[fd] = ctx;
        DEBUG_LOG("FD字典: 添加 fd=%d -> %s (目标=%d)", 
                  fd, path, ctx->is_target_dwg);
    }
    
    pthread_mutex_unlock(&fd_dict_mutex);
    return ctx;
}

/**
 * 从字典获取 FD 上下文
 */
static fd_context_t *get_fd_context(int fd) {
    if (fd < 0 || fd >= MAX_TRACKED_FD) {
        return NULL;
    }

    pthread_mutex_lock(&fd_dict_mutex);
    fd_context_t *ctx = fd_contexts[fd];
    pthread_mutex_unlock(&fd_dict_mutex);
    
    return ctx;
}

/**
 * 从字典移除 FD
 */
static void remove_fd_from_dict(int fd) {
    if (fd < 0 || fd >= MAX_TRACKED_FD) {
        return;
    }

    pthread_mutex_lock(&fd_dict_mutex);
    
    if (fd_contexts[fd]) {
        fd_context_t *ctx = fd_contexts[fd];
        ctx->ref_count--;
        
        DEBUG_LOG("FD字典: 移除 fd=%d, ref_count=%d", fd, ctx->ref_count);
        
        if (ctx->ref_count <= 0) {
            destroy_fd_context(ctx);
        }
        fd_contexts[fd] = NULL;
    }
    
    pthread_mutex_unlock(&fd_dict_mutex);
}

/**
 * 复制 FD 上下文（用于 dup 等操作）
 */
static void duplicate_fd_context(int old_fd, int new_fd) {
    if (old_fd < 0 || old_fd >= MAX_TRACKED_FD || 
        new_fd < 0 || new_fd >= MAX_TRACKED_FD) {
        return;
    }

    pthread_mutex_lock(&fd_dict_mutex);
    
    fd_context_t *old_ctx = fd_contexts[old_fd];
    if (old_ctx) {
        // 增加引用计数
        old_ctx->ref_count++;
        fd_contexts[new_fd] = old_ctx;
        
        DEBUG_LOG("FD字典: 复制 fd=%d -> fd=%d, ref_count=%d", 
                  old_fd, new_fd, old_ctx->ref_count);
    }
    
    pthread_mutex_unlock(&fd_dict_mutex);
}

// ==================== mmap 字典管理函数 ====================

/**
 * 查找空闲的 mmap 槽位
 */
static int find_free_mmap_slot() {
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_contexts[i].addr == NULL) {
            return i;
        }
    }
    return -1;
}

/**
 * 添加 mmap 区域到字典
 */
static mmap_context_t *add_mmap_to_dict(void *addr, size_t length, int prot, 
                                        int flags, int fd, off_t offset) {
    if (!addr || length == 0) {
        return NULL;
    }

    pthread_mutex_lock(&mmap_dict_mutex);
    
    int slot = find_free_mmap_slot();
    if (slot < 0) {
        pthread_mutex_unlock(&mmap_dict_mutex);
        DEBUG_LOG("mmap字典: 无可用槽位");
        return NULL;
    }
    
    mmap_context_t *ctx = &mmap_contexts[slot];
    memset(ctx, 0, sizeof(mmap_context_t));
    
    ctx->type = CRYPT_INFO_MAP;
    ctx->addr = addr;
    ctx->length = length;
    ctx->fd = fd;
    ctx->offset = offset;
    ctx->prot = prot;
    ctx->flags = flags;
    
    // 获取关联的文件上下文
    ctx->fd_ctx = get_fd_context(fd);
    if (ctx->fd_ctx && ctx->fd_ctx->is_target_dwg) {
        ctx->should_decrypt = true;
        ctx->in_memory_encrypted = true;  // 假设初始为加密状态
        ctx->disk_encrypted = true;
        
        DEBUG_LOG("mmap字典: 添加目标区域 addr=%p, len=%zu, fd=%d", 
                  addr, length, fd);
    } else {
        ctx->should_decrypt = false;
        ctx->in_memory_encrypted = false;
        ctx->disk_encrypted = false;
        
        DEBUG_LOG("mmap字典: 添加普通区域 addr=%p, len=%zu, fd=%d", 
                  addr, length, fd);
    }
    
    pthread_mutex_unlock(&mmap_dict_mutex);
    return ctx;
}

/**
 * 从字典获取 mmap 上下文
 */
static mmap_context_t *get_mmap_context(void *addr) {
    pthread_mutex_lock(&mmap_dict_mutex);
    
    mmap_context_t *result = NULL;
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_contexts[i].addr == NULL) continue;
        
        void *reg_start = mmap_contexts[i].addr;
        void *reg_end = (char*)reg_start + mmap_contexts[i].length;
        
        if (addr >= reg_start && addr < reg_end) {
            result = &mmap_contexts[i];
            break;
        }
    }
    
    pthread_mutex_unlock(&mmap_dict_mutex);
    return result;
}

/**
 * 从字典移除 mmap 区域
 */
static void remove_mmap_from_dict(void *addr) {
    pthread_mutex_lock(&mmap_dict_mutex);
    
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_contexts[i].addr == addr) {
            DEBUG_LOG("mmap字典: 移除区域 addr=%p, len=%zu", 
                      addr, mmap_contexts[i].length);
            mmap_contexts[i].addr = NULL;
            break;
        }
    }
    
    pthread_mutex_unlock(&mmap_dict_mutex);
}

/**
 * 标记 FD 相关的 mmap 区域为磁盘已加密
 */
static void mark_mmap_disk_encrypted_by_fd(int fd) {
    pthread_mutex_lock(&mmap_dict_mutex);
    
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_contexts[i].addr != NULL && mmap_contexts[i].fd == fd) {
            mmap_contexts[i].disk_encrypted = true;
            DEBUG_LOG("标记 mmap 区域 fd=%d addr=%p 为 disk_encrypted=true", 
                      fd, mmap_contexts[i].addr);
        }
    }
    
    pthread_mutex_unlock(&mmap_dict_mutex);
}

/**
 * 标记指定范围的 mmap 区域为磁盘已加密
 */
static void mark_mmap_disk_encrypted_by_range(int fd, off_t offset, size_t count) {
    pthread_mutex_lock(&mmap_dict_mutex);
    
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_contexts[i].addr == NULL || mmap_contexts[i].fd != fd) {
            continue;
        }
        
        off_t reg_start = mmap_contexts[i].offset;
        off_t reg_end = mmap_contexts[i].offset + (off_t)mmap_contexts[i].length;
        off_t write_start = offset;
        off_t write_end = offset + (off_t)count;
        
        // 检查是否有交集
        if (!(write_end <= reg_start || write_start >= reg_end)) {
            mmap_contexts[i].disk_encrypted = true;
            DEBUG_LOG("标记 mmap 区域范围 fd=%d 为 disk_encrypted=true", fd);
        }
    }
    
    pthread_mutex_unlock(&mmap_dict_mutex);
}

// ==================== 加解密工具函数 ====================

/**
 * 获取内存保护权限
 */
static int get_memory_protection(void *addr) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        return PROT_NONE;
    }
    
    int protection = PROT_NONE;
    char line[256];
    unsigned long start, end;
    uintptr_t addr_val = (uintptr_t)addr;
    
    while (fgets(line, sizeof(line), maps)) {
        char perms[5] = {0};
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            if (start <= addr_val && addr_val < end) {
                protection = 0;
                if (perms[0] == 'r') protection |= PROT_READ;
                if (perms[1] == 'w') protection |= PROT_WRITE;
                if (perms[2] == 'x') protection |= PROT_EXEC;
                break;
            }
        }
    }
    
    fclose(maps);
    return protection;
}

/**
 * 安全解密内存区域
 */
static int safe_decrypt_memory(void *addr, size_t length) {
    if (!addr || length == 0) {
        return -1;
    }

    int orig_prot = get_memory_protection(addr);
    
    // 处理只读内存
    if ((orig_prot & PROT_WRITE) == 0) {
        void *new_map = mmap(NULL, length, PROT_READ | PROT_WRITE, 
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (new_map == MAP_FAILED) {
            return -1;
        }
        
        memcpy(new_map, addr, length);
        
        unsigned char *data = (unsigned char *)new_map;
        for (size_t i = 0; i < length; ++i) {
            data[i] ^= 0xFF;
        }
        
        if (munmap(addr, length)) {
            munmap(new_map, length);
            return -1;
        }
        
        void *remap = mmap(addr, length, PROT_READ | PROT_WRITE, 
                          MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
        if (remap != addr) {
            munmap(new_map, length);
            return -1;
        }
        
        memcpy(addr, new_map, length);
        munmap(new_map, length);
        
        if (mprotect(addr, length, orig_prot)) {
            DEBUG_LOG("恢复权限失败: %s", strerror(errno));
        }
        
        return 0;
    }

    // 处理可写内存
    if (mprotect(addr, length, PROT_READ | PROT_WRITE) != 0) {
        return -1;
    }

    unsigned char *data = (unsigned char *)addr;
    for (size_t i = 0; i < length; ++i) {
        data[i] ^= 0xFF;
    }

    if (mprotect(addr, length, orig_prot) != 0) {
        DEBUG_LOG("恢复权限失败: %s", strerror(errno));
    }

    return 0;
}

/**
 * 安全加密内存区域
 */
static int safe_encrypt_memory(void *addr, size_t length) {
    if (!addr || length == 0) {
        return -1;
    }

    if (mprotect(addr, length, PROT_READ | PROT_WRITE) != 0) {
        return -1;
    }

    unsigned char *data = (unsigned char *)addr;
    for (size_t i = 0; i < length; ++i) {
        data[i] ^= 0xFF;
    }

    if (mprotect(addr, length, PROT_READ) != 0) {
        DEBUG_LOG("恢复权限失败: %s", strerror(errno));
    }

    return 0;
}

/**
 * 加密磁盘文件
 */
static int encrypt_file_on_disk(const char *path) {
    if (!path) return -1;
    
    int fd = open(path, O_RDWR);
    if (fd < 0) {
        DEBUG_LOG("无法打开文件进行加密: %s, 错误: %s", path, strerror(errno));
        return -1;
    }

    // 简单检查是否为明文 DWG
    unsigned char hdr[8] = {0};
    ssize_t r = pread(fd, hdr, sizeof(hdr), 0);
    if (r <= 0) {
        DEBUG_LOG("无法读取文件头: %s", path);
        close(fd);
        return -1;
    }
    
    DEBUG_LOG("文件头检查: %s, 前8字节: %02X %02X %02X %02X %02X %02X %02X %02X", 
              path, hdr[0], hdr[1], hdr[2], hdr[3], hdr[4], hdr[5], hdr[6], hdr[7]);
    
    // 检查是否为明文 DWG (AC1xxx 格式)
    if (!(hdr[0] == 'A' && hdr[1] == 'C' && hdr[2] == '1')) {
        DEBUG_LOG("跳过非明文 DWG 文件: %s", path);
        close(fd);
        return 0;
    }

    off_t size = lseek(fd, 0, SEEK_END);
    if (size == (off_t)-1) {
        DEBUG_LOG("无法获取文件大小: %s", path);
        close(fd);
        return -1;
    }
    
    DEBUG_LOG("开始加密文件: %s, 大小: %ld 字节", path, (long)size);

    const size_t CHUNK_SIZE = 64 * 1024;
    unsigned char *buf = malloc(CHUNK_SIZE);
    if (!buf) {
        DEBUG_LOG("内存分配失败");
        close(fd);
        return -1;
    }

    off_t off = 0;
    while (off < size) {
        size_t toread = (size - off) > CHUNK_SIZE ? CHUNK_SIZE : (size - off);
        ssize_t n = pread(fd, buf, toread, off);
        if (n <= 0) break;
        
        for (ssize_t i = 0; i < n; ++i) {
            buf[i] ^= 0xFF;
        }
        
        ssize_t w = pwrite(fd, buf, n, off);
        if (w != n) break;
        
        off += n;
    }

    free(buf);
    fsync(fd);
    close(fd);
    
    DEBUG_LOG("文件加密完成: %s", path);
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

    int fd;
    if (flags & O_CREAT) {
        fd = real_openat(dirfd, pathname, flags, mode);
    } else {
        fd = real_openat(dirfd, pathname, flags);
    }

    if (fd >= 0 && pathname) {
        // 处理相对路径，转换为绝对路径
        char resolved_path[PATH_MAX];
        char *abs_path = NULL;
        
        if (pathname[0] == '/') {
            // 已经是绝对路径
            abs_path = (char*)pathname;
        } else {
            // 相对路径，需要解析
            if (dirfd == AT_FDCWD) {
                if (realpath(pathname, resolved_path) != NULL) {
                    abs_path = resolved_path;
                } else {
                    abs_path = (char*)pathname;
                }
            } else {
                // 相对于特定目录的路径，简化处理
                abs_path = (char*)pathname;
            }
        }
        
        fd_context_t *ctx = add_fd_to_dict(fd, abs_path, flags);
        DEBUG_LOG("openat: fd=%d -> '%s' (目标=%d)", 
                  fd, abs_path, ctx ? ctx->is_target_dwg : 0);
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

    int fd;
    if (flags & O_CREAT) {
        fd = real_open(pathname, flags, mode);
    } else {
        fd = real_open(pathname, flags);
    }

    if (fd >= 0 && pathname) {
        // 处理相对路径，转换为绝对路径
        char resolved_path[PATH_MAX];
        char *abs_path = NULL;
        
        if (pathname[0] == '/') {
            // 已经是绝对路径
            abs_path = (char*)pathname;
        } else {
            // 相对路径，需要解析
            if (realpath(pathname, resolved_path) != NULL) {
                abs_path = resolved_path;
            } else {
                abs_path = (char*)pathname;
            }
        }
        
        fd_context_t *ctx = add_fd_to_dict(fd, abs_path, flags);
        DEBUG_LOG("open: fd=%d -> '%s' (目标=%d)", 
                  fd, abs_path, ctx ? ctx->is_target_dwg : 0);
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
    if (ret <= 0) {
        return ret;
    }

    // 从字典获取上下文
    fd_context_t *ctx = get_fd_context(fd);
    if (ctx && ctx->is_target_dwg) {
        DEBUG_LOG("pread64: 解密目标文件 fd=%d, 路径=%s, 偏移=%ld, 大小=%zu", 
                  fd, ctx->file_path, (long)offset, count);
        
        unsigned char *data = (unsigned char *)buf;
        for (ssize_t i = 0; i < ret; ++i) {
            data[i] ^= 0xFF;
        }
        
        DEBUG_LOG("pread64: 解密完成 %zd 字节, 前4字节: %02X %02X %02X %02X", 
                  ret, data[0], data[1], data[2], data[3]);
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
    if (ret <= 0) {
        return ret;
    }

    // 从字典获取上下文
    fd_context_t *ctx = get_fd_context(fd);
    if (ctx && ctx->is_target_dwg) {
        DEBUG_LOG("read: 解密目标文件 fd=%d, 路径=%s, 当前偏移=%ld, 大小=%zu", 
                  fd, ctx->file_path, (long)ctx->current_offset, count);
        
        unsigned char *data = (unsigned char *)buf;
        for (ssize_t i = 0; i < ret; ++i) {
            data[i] ^= 0xFF;
        }
        
        // 更新文件偏移
        ctx->current_offset += ret;
        DEBUG_LOG("read: 解密完成 %zd 字节, 前4字节: %02X %02X %02X %02X", 
                  ret, data[0], data[1], data[2], data[3]);
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

    void *ptr = real_mmap(addr, length, prot, flags, fd, offset);
    if (ptr == MAP_FAILED) {
        return ptr;
    }

    // 添加到 mmap 字典
    mmap_context_t *mmap_ctx = add_mmap_to_dict(ptr, length, prot, flags, fd, offset);
    
    if (mmap_ctx && mmap_ctx->should_decrypt) {
        DEBUG_LOG("mmap: 解密目标区域 addr=%p, len=%zu, fd=%d", ptr, length, fd);
        
        if (safe_decrypt_memory(ptr, length) == 0) {
            mmap_ctx->in_memory_encrypted = false;
            DEBUG_LOG("mmap: 内存解密成功");
        } else {
            DEBUG_LOG("mmap: 内存解密失败");
        }
    }

    return ptr;
}

/**
 * 拦截 mmap64 系统调用
 */
void *mmap64(void *addr, size_t length, int prot, int flags, int fd, off64_t offset) {
    static void *(*real_mmap64)(void *, size_t, int, int, int, off64_t) = NULL;
    if (!real_mmap64)
        real_mmap64 = dlsym(RTLD_NEXT, "mmap64");

    void *ptr = real_mmap64(addr, length, prot, flags, fd, offset);
    if (ptr == MAP_FAILED) {
        return ptr;
    }

    // 添加到 mmap 字典
    mmap_context_t *mmap_ctx = add_mmap_to_dict(ptr, length, prot, flags, fd, (off_t)offset);
    
    if (mmap_ctx && mmap_ctx->should_decrypt) {
        DEBUG_LOG("mmap64: 解密目标区域 addr=%p, len=%zu, fd=%d", ptr, length, fd);
        
        if (safe_decrypt_memory(ptr, length) == 0) {
            mmap_ctx->in_memory_encrypted = false;
            DEBUG_LOG("mmap64: 内存解密成功");
        } else {
            DEBUG_LOG("mmap64: 内存解密失败");
        }
    }

    return ptr;
}

/**
 * 拦截 munmap 系统调用
 */
int munmap(void *addr, size_t length) {
    static int (*real_munmap)(void *, size_t) = NULL;
    if (!real_munmap)
        real_munmap = dlsym(RTLD_NEXT, "munmap");

    // 获取 mmap 上下文
    mmap_context_t *ctx = get_mmap_context(addr);
    
    if (ctx && ctx->should_decrypt && ctx->modified && !ctx->disk_encrypted) {
        DEBUG_LOG("munmap: 需要加密区域 addr=%p, len=%zu", addr, length);
        
        if (safe_encrypt_memory(addr, length) == 0) {
            ctx->in_memory_encrypted = true;
            ctx->disk_encrypted = true;
            ctx->modified = false;
            
            // 同步到磁盘
            if (ctx->fd >= 0) {
                msync(addr, length, MS_SYNC);
            }
            
            DEBUG_LOG("munmap: 加密并同步完成");
        }
    }

    int ret = real_munmap(addr, length);
    if (ret == 0) {
        remove_mmap_from_dict(addr);
    }

    return ret;
}

/**
 * 拦截 write 系统调用
 */
ssize_t write(int fd, const void *buf, size_t count) {
    static ssize_t (*real_write)(int, const void *, size_t) = NULL;
    if (!real_write)
        real_write = dlsym(RTLD_NEXT, "write");

    // 从字典获取上下文
    fd_context_t *ctx = get_fd_context(fd);
    
    if (!ctx || !ctx->is_target_dwg || count == 0 || !buf) {
        return real_write(fd, buf, count);
    }

    DEBUG_LOG("write: 加密写入 fd=%d, 路径=%s, 大小=%zu", 
              fd, ctx->file_path, count);

    // 加密后写入
    void *encrypted_buf = malloc(count);
    if (!encrypted_buf) {
        errno = ENOMEM;
        return -1;
    }

    memcpy(encrypted_buf, buf, count);
    unsigned char *data = (unsigned char *)encrypted_buf;
    for (size_t i = 0; i < count; i++) {
        data[i] ^= 0xFF;
    }

    ssize_t ret = real_write(fd, encrypted_buf, count);
    free(encrypted_buf);

    if (ret >= 0) {
        // 更新文件偏移
        ctx->current_offset += ret;
        // 标记相关 mmap 区域
        mark_mmap_disk_encrypted_by_fd(fd);
    }

    return ret;
}

/**
 * 拦截 pwrite64 系统调用
 */
ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset) {
    static ssize_t (*real_pwrite64)(int, const void *, size_t, off_t) = NULL;
    if (!real_pwrite64)
        real_pwrite64 = dlsym(RTLD_NEXT, "pwrite64");

    // 从字典获取上下文
    fd_context_t *ctx = get_fd_context(fd);
    
    if (!ctx || !ctx->is_target_dwg || count == 0 || !buf) {
        return real_pwrite64(fd, buf, count, offset);
    }

    DEBUG_LOG("pwrite64: 加密写入 fd=%d, 路径=%s, 偏移=%ld, 大小=%zu", 
              fd, ctx->file_path, (long)offset, count);

    // 加密后写入
    void *encrypted_buf = malloc(count);
    if (!encrypted_buf) {
        errno = ENOMEM;
        return -1;
    }

    memcpy(encrypted_buf, buf, count);
    unsigned char *data = (unsigned char *)encrypted_buf;
    for (size_t i = 0; i < count; i++) {
        data[i] ^= 0xFF;
    }

    ssize_t ret = real_pwrite64(fd, encrypted_buf, count, offset);
    free(encrypted_buf);

    if (ret >= 0) {
        // 标记相关 mmap 区域
        mark_mmap_disk_encrypted_by_range(fd, offset, count);
    }

    return ret;
}

/**
 * 拦截 msync 系统调用
 */
int msync(void *addr, size_t length, int flags) {
    static int (*real_msync)(void *, size_t, int) = NULL;
    if (!real_msync)
        real_msync = dlsym(RTLD_NEXT, "msync");

    mmap_context_t *ctx = get_mmap_context(addr);
    
    if (ctx && ctx->should_decrypt && ctx->modified && !ctx->disk_encrypted) {
        DEBUG_LOG("msync: 需要加密同步 addr=%p, len=%zu", addr, length);
        
        if (safe_encrypt_memory(addr, length) == 0) {
            ctx->in_memory_encrypted = true;
            ctx->disk_encrypted = true;
            
            int ret = real_msync(addr, length, flags);
            
            // 解密回内存
            if (!ctx->in_memory_encrypted) {
                safe_decrypt_memory(addr, length);
            }
            
            ctx->modified = false;
            return ret;
        }
    }

    return real_msync(addr, length, flags);
}

/**
 * 拦截 mprotect 系统调用
 */
int mprotect(void *addr, size_t len, int prot) {
    static int (*real_mprotect)(void *, size_t, int) = NULL;
    if (!real_mprotect)
        real_mprotect = dlsym(RTLD_NEXT, "mprotect");
    
    // 更新 mmap 上下文
    mmap_context_t *ctx = get_mmap_context(addr);
    if (ctx) {
        ctx->prot = prot;
        if (prot & PROT_WRITE) {
            ctx->modified = true;
            ctx->disk_encrypted = false;
            DEBUG_LOG("mprotect: 标记区域 %p 为可写已修改", addr);
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

    int ret = real_rename(oldpath, newpath);

    if (ret == 0 && newpath && is_target_dwg_file(newpath)) {
        DEBUG_LOG("rename: 对新文件加密 %s", newpath);
        encrypt_file_on_disk(newpath);
    }

    return ret;
}

/**
 * 拦截 renameat 系统调用
 */
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    static int (*real_renameat)(int, const char *, int, const char *) = NULL;
    if (!real_renameat) 
        real_renameat = dlsym(RTLD_NEXT, "renameat");

    int ret = real_renameat(olddirfd, oldpath, newdirfd, newpath);

    if (ret == 0 && newpath) {
        if ((newpath[0] == '/' && is_target_dwg_file(newpath)) ||
            (newdirfd == AT_FDCWD && is_target_dwg_file(newpath))) {
            DEBUG_LOG("renameat: 对新文件加密 %s", newpath);
            encrypt_file_on_disk(newpath);
        }
    }

    return ret;
}

/**
 * 拦截 lseek 系统调用
 */
off_t lseek(int fd, off_t offset, int whence) {
    static off_t (*real_lseek)(int, off_t, int) = NULL;
    if (!real_lseek)
        real_lseek = dlsym(RTLD_NEXT, "lseek");

    off_t ret = real_lseek(fd, offset, whence);
    
    // 更新文件上下文中的偏移信息
    fd_context_t *ctx = get_fd_context(fd);
    if (ctx && ret != (off_t)-1) {
        ctx->current_offset = ret;
        if (ctx->is_target_dwg) {
            DEBUG_LOG("lseek: fd=%d, 新偏移=%ld", fd, (long)ret);
        }
    }
    
    return ret;
}

/**
 * 拦截 lseek64 系统调用
 */
off64_t lseek64(int fd, off64_t offset, int whence) {
    static off64_t (*real_lseek64)(int, off64_t, int) = NULL;
    if (!real_lseek64)
        real_lseek64 = dlsym(RTLD_NEXT, "lseek64");

    off64_t ret = real_lseek64(fd, offset, whence);
    
    // 更新文件上下文中的偏移信息
    fd_context_t *ctx = get_fd_context(fd);
    if (ctx && ret != (off64_t)-1) {
        ctx->current_offset = (off_t)ret;
        if (ctx->is_target_dwg) {
            DEBUG_LOG("lseek64: fd=%d, 新偏移=%ld", fd, (long)ret);
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

    // 获取上下文信息用于日志
    fd_context_t *ctx = get_fd_context(fd);
    if (ctx) {
        DEBUG_LOG("close: fd=%d, 路径=%s", fd, ctx->file_path);
    }

    int ret = real_close(fd);

    if (ret == 0) {
        // 从字典移除
        remove_fd_from_dict(fd);
    }

    return ret;
}

/**
 * 拦截 dup 系统调用
 */
int dup(int oldfd) {
    static int (*real_dup)(int) = NULL;
    if (!real_dup)
        real_dup = dlsym(RTLD_NEXT, "dup");

    int newfd = real_dup(oldfd);
    if (newfd >= 0) {
        duplicate_fd_context(oldfd, newfd);
        DEBUG_LOG("dup: %d -> %d", oldfd, newfd);
    }

    return newfd;
}

/**
 * 拦截 dup2 系统调用
 */
int dup2(int oldfd, int newfd) {
    static int (*real_dup2)(int, int) = NULL;
    if (!real_dup2)
        real_dup2 = dlsym(RTLD_NEXT, "dup2");

    int ret = real_dup2(oldfd, newfd);
    if (ret >= 0) {
        duplicate_fd_context(oldfd, newfd);
        DEBUG_LOG("dup2: %d -> %d", oldfd, newfd);
    }

    return ret;
}