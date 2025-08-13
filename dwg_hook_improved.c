// 文件路径: /home/chane/tif_crypto_hook/dwg_hook_improved.c
//
// 编译命令:
//   gcc -shared -fPIC -o libdwg_hook_improved.so dwg_hook_improved.c -ldl -lpthread
//
// 使用方法:
//   export DWG_HOOK_DEBUG=1
//   LD_PRELOAD=/home/chane/tif_crypto_hook/libdwg_hook_improved.so ./ZWCAD "$@" /product ZWCAD

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
#include <time.h>
#include <locale.h>

// ==================== 配置与全局调试 ====================

#define MAX_TRACKED_FD 1024
#define DWG_MAGIC_SIZE 32
#define LOG_FILE_PATH "/tmp/dwg_hook.log"

// 调试标志：控制是否输出调试日志
static int debug_enabled = -1;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/** 获取当前时间戳字符串 */
static void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

/** 初始化调试标志和UTF-8支持 */
static void init_debug_flags(void) {
    if (debug_enabled == -1) {
        // 设置UTF-8 locale支持中文
        setlocale(LC_ALL, "zh_CN.UTF-8");
        
        const char *env = getenv("DWG_HOOK_DEBUG");
        debug_enabled = (env && strcmp(env, "1") == 0) ? 1 : 0;
        
        if (debug_enabled) {
            // 确保日志文件以UTF-8编码创建
            FILE *logfp = fopen(LOG_FILE_PATH, "w");
            if (logfp) {
                // 添加UTF-8 BOM头确保正确显示中文
                unsigned char bom[] = {0xEF, 0xBB, 0xBF};
                fwrite(bom, 1, 3, logfp);
                fprintf(logfp, "=== DWG透明加解密Hook库日志 ===\n");
                fprintf(logfp, "编码: UTF-8\n");
                fprintf(logfp, "日志文件: %s\n", LOG_FILE_PATH);
                fclose(logfp);
            }
        }
    }
}

/** 线程安全的调试日志输出宏 */
#define DEBUG_LOG(fmt, ...) \
    do { \
        init_debug_flags(); \
        if (debug_enabled) { \
            pthread_mutex_lock(&log_mutex); \
            FILE *logfp = fopen(LOG_FILE_PATH, "a"); \
            if (logfp) { \
                char timestamp[64]; \
                get_timestamp(timestamp, sizeof(timestamp)); \
                fprintf(logfp, "[%s][PID:%d][TID:%ld] " fmt "\n", \
                        timestamp, getpid(), (long)pthread_self(), ##__VA_ARGS__); \
                fflush(logfp); \
                fclose(logfp); \
            } \
            pthread_mutex_unlock(&log_mutex); \
        } \
    } while (0)

/** 输出前3个字节的十六进制数据 */
static void log_hex_3_bytes(const char *prefix, const unsigned char *data, size_t total_len) {
    if (!debug_enabled || !data) return;
    
    pthread_mutex_lock(&log_mutex);
    FILE *logfp = fopen(LOG_FILE_PATH, "a");
    if (logfp) {
        char timestamp[64];
        get_timestamp(timestamp, sizeof(timestamp));
        fprintf(logfp, "[%s][PID:%d][TID:%ld] %s (总长度:%zu): ", 
                timestamp, getpid(), (long)pthread_self(), prefix, total_len);
        
        size_t show_len = (total_len < 3) ? total_len : 3;
        for (size_t i = 0; i < show_len; i++) {
            fprintf(logfp, "%02X ", data[i]);
        }
        if (total_len > 3) {
            fprintf(logfp, "...");
        }
        fprintf(logfp, "\n");
        fflush(logfp);
        fclose(logfp);
    }
    pthread_mutex_unlock(&log_mutex);
}

// ==================== 增强的文件检测逻辑 ====================

/**
 * 检查文件内容是否为DWG格式
 * DWG文件通常以"AC1xxx"开头，其中xxx是版本号
 */
static int is_dwg_content(const unsigned char *data, size_t size) {
    if (size < 6) return 0;
    
    // 检查DWG文件头 "AC1" + 版本
    if (data[0] == 'A' && data[1] == 'C' && data[2] == '1') {
        DEBUG_LOG("检测到明文DWG文件头: AC1xxx");
        return 1;
    }
    
    // 检查是否为加密的DWG（异或后的内容）
    unsigned char decrypted[6];
    for (int i = 0; i < 6; i++) {
        decrypted[i] = data[i] ^ 0xFF;
    }
    if (decrypted[0] == 'A' && decrypted[1] == 'C' && decrypted[2] == '1') {
        DEBUG_LOG("检测到加密DWG文件头: 需要解密才能看到AC1xxx");
        return 2; // 表示是加密的DWG
    }
    
    return 0;
}

/**
 * 改进的目标文件判定：
 * 1) 扩展名为 .dwg（不区分大小写）
 * 2) 处理所有DWG文件，移除"changed_"限制
 * 3) 支持绝对路径和相对路径
 */
static int is_target_dwg_file(const char *path) {
    if (!path) return 0;

    size_t len = strlen(path);
    if (len < 4) return 0;

    const char *ext = path + len - 4;
    if (strcasecmp(ext, ".dwg") != 0) return 0;

    // 排除临时文件和系统文件
    const char *filename = strrchr(path, '/');
    if (filename) filename++;
    else filename = path;
    
    if (filename[0] == '.' || strstr(filename, "tmp") || strstr(filename, "temp")) {
        DEBUG_LOG("跳过临时文件: %s", path);
        return 0;
    }

    DEBUG_LOG("确认为目标DWG文件: %s", path);
    return 1;
}

/**
 * 通过文件描述符检查文件内容类型
 */
static int check_fd_content_type(int fd) {
    if (fd < 0) return 0;
    
    unsigned char buffer[DWG_MAGIC_SIZE];
    ssize_t bytes_read = pread(fd, buffer, sizeof(buffer), 0);
    if (bytes_read < 6) {
        DEBUG_LOG("文件内容太短，无法检测DWG格式: fd=%d, 读取字节=%zd", fd, bytes_read);
        return 0;
    }
    
    int content_type = is_dwg_content(buffer, bytes_read);
    DEBUG_LOG("文件内容类型检测结果: fd=%d, 类型=%d (0=未知, 1=明文DWG, 2=加密DWG)", 
              fd, content_type);
    return content_type;
}

// ==================== FD→上下文字典（哈希表） ====================

typedef struct {
    int   is_target;           // 是否目标DWG：1=是，0=否
    char *path;                // 真实路径（open 时解析）
    bool  should_decrypt;      // 是否需要在读/映射时解密
    bool  disk_encrypted;      // 认为磁盘侧当前为加密态
    bool  in_memory_encrypted; // 认为内存侧当前为加密态
    int   content_type;        // 文件内容类型：0=未知，1=明文DWG，2=加密DWG
    off_t file_size;           // 文件大小
} fd_context_t;

#define FD_HASH_SIZE 1024

typedef struct fd_node {
    int fd;
    fd_context_t ctx;
    struct fd_node *next;
} fd_node_t;

static fd_node_t *fd_table[FD_HASH_SIZE] = {0};
static pthread_mutex_t fd_table_mutex = PTHREAD_MUTEX_INITIALIZER;

static inline unsigned int fd_hash(int fd) {
    return ((unsigned int)fd) % FD_HASH_SIZE;
}

/** 插入/更新 FD 上下文 */
static void fd_ctx_set(int fd, const fd_context_t *ctx) {
    pthread_mutex_lock(&fd_table_mutex);
    unsigned int h = fd_hash(fd);
    fd_node_t *n = fd_table[h];
    while (n) {
        if (n->fd == fd) {
            // 覆盖旧值
            free(n->ctx.path);
            n->ctx = *ctx;
            n->ctx.path = ctx->path ? strdup(ctx->path) : NULL;
            pthread_mutex_unlock(&fd_table_mutex);
            DEBUG_LOG("更新FD上下文成功: fd=%d", fd);
            return;
        }
        n = n->next;
    }
    // 新建
    n = (fd_node_t *)calloc(1, sizeof(fd_node_t));
    n->fd = fd;
    n->ctx = *ctx;
    n->ctx.path = ctx->path ? strdup(ctx->path) : NULL;
    n->next = fd_table[h];
    fd_table[h] = n;
    pthread_mutex_unlock(&fd_table_mutex);
    DEBUG_LOG("创建FD上下文成功: fd=%d", fd);
}

/** 获取 FD 上下文的拷贝 */
static int fd_ctx_get_copy(int fd, fd_context_t *out) {
    int ok = 0;
    pthread_mutex_lock(&fd_table_mutex);
    fd_node_t *n = fd_table[fd_hash(fd)];
    while (n) {
        if (n->fd == fd) {
            *out = n->ctx;
            out->path = n->ctx.path ? strdup(n->ctx.path) : NULL;
            ok = 1;
            break;
        }
        n = n->next;
    }
    pthread_mutex_unlock(&fd_table_mutex);
    return ok;
}

/** 更新FD上下文的内容类型和大小 */
static void fd_ctx_update_content_info(int fd, int content_type, off_t file_size) {
    pthread_mutex_lock(&fd_table_mutex);
    fd_node_t *n = fd_table[fd_hash(fd)];
    while (n) {
        if (n->fd == fd) {
            n->ctx.content_type = content_type;
            n->ctx.file_size = file_size;
            // 根据内容类型调整加解密策略
            if (content_type == 2) { // 加密的DWG
                n->ctx.should_decrypt = true;
                n->ctx.disk_encrypted = true;
                n->ctx.in_memory_encrypted = true;
                DEBUG_LOG("设置解密策略: fd=%d, 文件为加密DWG", fd);
            } else if (content_type == 1) { // 明文DWG
                n->ctx.should_decrypt = false;
                n->ctx.disk_encrypted = false;
                n->ctx.in_memory_encrypted = false;
                DEBUG_LOG("设置明文策略: fd=%d, 文件为明文DWG", fd);
            }
            break;
        }
        n = n->next;
    }
    pthread_mutex_unlock(&fd_table_mutex);
}

/** 仅更新布尔标记 */
static void fd_ctx_update_flags(int fd, bool *disk_encrypted, bool *in_memory_encrypted) {
    pthread_mutex_lock(&fd_table_mutex);
    fd_node_t *n = fd_table[fd_hash(fd)];
    while (n) {
        if (n->fd == fd) {
            if (disk_encrypted)       n->ctx.disk_encrypted = *disk_encrypted;
            if (in_memory_encrypted)  n->ctx.in_memory_encrypted = *in_memory_encrypted;
            DEBUG_LOG("更新FD状态标记: fd=%d", fd);
            break;
        }
        n = n->next;
    }
    pthread_mutex_unlock(&fd_table_mutex);
}

/** 移除 FD 上下文 */
static void fd_ctx_remove(int fd) {
    pthread_mutex_lock(&fd_table_mutex);
    unsigned int h = fd_hash(fd);
    fd_node_t **pp = &fd_table[h];
    while (*pp) {
        if ((*pp)->fd == fd) {
            fd_node_t *tmp = *pp;
            *pp = tmp->next;
            free(tmp->ctx.path);
            free(tmp);
            DEBUG_LOG("移除FD上下文: fd=%d", fd);
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&fd_table_mutex);
}

// ==================== 内存映射追踪 ====================

typedef struct {
    void *addr;
    size_t length;
    int should_decrypt;
    int prot;
    int flags;
    int fd;
    off_t offset;
    bool modified;
    bool in_memory_encrypted;
    bool disk_encrypted;
} mmap_region_t;

#define MAX_MMAP_REGIONS 512
static mmap_region_t mmap_regions[MAX_MMAP_REGIONS] = {0};
static pthread_mutex_t mmap_mutex = PTHREAD_MUTEX_INITIALIZER;

/** 查找空槽 */
static int find_free_mmap_slot_locked(void) {
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == NULL) return i;
    }
    return -1;
}

/** 按地址查找 region */
static mmap_region_t *find_mmap_region(void *addr) {
    pthread_mutex_lock(&mmap_mutex);
    mmap_region_t *result = NULL;
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (!mmap_regions[i].addr) continue;
        char *start = (char *)mmap_regions[i].addr;
        char *end   = start + mmap_regions[i].length;
        if ((char *)addr >= start && (char *)addr < end) {
            result = &mmap_regions[i];
            break;
        }
    }
    pthread_mutex_unlock(&mmap_mutex);
    return result;
}

/** 记录 mmap 区域 */
static void track_mmap_region(void *addr, size_t length, int should_decrypt, int prot, int flags, int fd, off_t offset) {
    if (!addr || length == 0) return;
    pthread_mutex_lock(&mmap_mutex);
    int slot = find_free_mmap_slot_locked();
    if (slot >= 0) {
        mmap_regions[slot].addr = addr;
        mmap_regions[slot].length = length;
        mmap_regions[slot].should_decrypt = should_decrypt;
        mmap_regions[slot].prot = prot;
        mmap_regions[slot].flags = flags;
        mmap_regions[slot].fd = fd;
        mmap_regions[slot].offset = offset;
        mmap_regions[slot].modified = false;
        mmap_regions[slot].in_memory_encrypted = should_decrypt ? true : false;
        mmap_regions[slot].disk_encrypted = should_decrypt ? true : false;
        DEBUG_LOG("mmap区域跟踪成功: slot=%d, addr=%p, len=%zu, fd=%d, should_decrypt=%s",
                  slot, addr, length, fd, should_decrypt ? "是" : "否");
    } else {
        DEBUG_LOG("警告: 无可用mmap插槽来跟踪 addr=%p len=%zu", addr, length);
    }
    pthread_mutex_unlock(&mmap_mutex);
}

/** 解除 mmap 区域跟踪 */
static void untrack_mmap_region(void *addr) {
    pthread_mutex_lock(&mmap_mutex);
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == addr) {
            DEBUG_LOG("解除mmap跟踪: 地址=%p, 长度=%zu", addr, mmap_regions[i].length);
            mmap_regions[i].addr = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&mmap_mutex);
}

// ==================== 加解密工具函数 ====================

/** 异或加密/解密 */
static void xor_encrypt_decrypt(unsigned char *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= 0xFF;
    }
}

/** 安全的内存区域解密 */
static int safe_decrypt_memory(void *addr, size_t length) {
    if (!addr || length == 0) return -1;
    
    // 临时设置写权限
    if (mprotect(addr, length, PROT_READ | PROT_WRITE) != 0) {
        DEBUG_LOG("mprotect设置写权限失败: %s", strerror(errno));
        return -1;
    }
    
    DEBUG_LOG("开始内存区域解密: addr=%p, 长度=%zu", addr, length);
    log_hex_3_bytes("内存解密前", (unsigned char *)addr, length);
    
    xor_encrypt_decrypt((unsigned char *)addr, length);
    
    log_hex_3_bytes("内存解密后", (unsigned char *)addr, length);
    
    // 恢复只读权限
    if (mprotect(addr, length, PROT_READ) != 0) {
        DEBUG_LOG("mprotect恢复只读权限失败: %s", strerror(errno));
    }
    
    DEBUG_LOG("内存区域解密完成");
    return 0;
}

/** 检查并解密内存映射区域 */
static int check_and_decrypt_mmap_region(void *addr, size_t length, int fd) {
    if (!addr || length == 0) return 0;
    
    // 检查是否为DWG内容
    int content_type = is_dwg_content((unsigned char *)addr, length > DWG_MAGIC_SIZE ? DWG_MAGIC_SIZE : length);
    
    if (content_type == 2) { // 加密的DWG
        DEBUG_LOG("检测到加密DWG内容，开始解密 addr=%p len=%zu", addr, length);
        if (safe_decrypt_memory(addr, length) == 0) {
            DEBUG_LOG("mmap区域解密成功");
            return 1;
        } else {
            DEBUG_LOG("mmap区域解密失败");
        }
    } else if (content_type == 1) {
        DEBUG_LOG("检测到明文DWG内容 addr=%p len=%zu", addr, length);
    } else {
        DEBUG_LOG("未检测到DWG内容 addr=%p len=%zu", addr, length);
    }
    
    return 0;
}

// ==================== Hook 实现：文件打开 ====================

int openat(int dirfd, const char *pathname, int flags, ...) {
    static int (*real_openat)(int, const char *, int, ...) = NULL;
    if (!real_openat) {
        real_openat = dlsym(RTLD_NEXT, "openat");
        DEBUG_LOG("openat Hook已加载: real_openat=%p", real_openat);
    }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    int fd = (flags & O_CREAT) ? real_openat(dirfd, pathname, flags, mode)
                               : real_openat(dirfd, pathname, flags);
    
    if (fd >= 0 && pathname) {
        DEBUG_LOG("openat Hook调用成功: pathname='%s', fd=%d, flags=0x%x", pathname, fd, flags);
        
        // 构造绝对路径
        char *resolved = NULL;
        if (pathname[0] == '/') {
            resolved = strdup(pathname);
        } else {
            resolved = realpath(pathname, NULL);
            if (!resolved) resolved = strdup(pathname);
        }
        
        fd_context_t ctx = {0};
        ctx.path = resolved;
        ctx.is_target = is_target_dwg_file(resolved);
        
        if (ctx.is_target) {
            // 检查文件内容类型
            ctx.content_type = check_fd_content_type(fd);
            ctx.should_decrypt = (ctx.content_type == 2); // 只有加密的才需要解密
            ctx.disk_encrypted = (ctx.content_type == 2);
            ctx.in_memory_encrypted = (ctx.content_type == 2);
            
            // 获取文件大小
            struct stat st;
            if (fstat(fd, &st) == 0) {
                ctx.file_size = st.st_size;
            }
            
            DEBUG_LOG("=====【成功打开目标DWG文件】=====");
            DEBUG_LOG("文件描述符: %d", fd);
            DEBUG_LOG("绝对路径: %s", resolved);
            DEBUG_LOG("文件大小: %ld 字节", (long)ctx.file_size);
            DEBUG_LOG("内容类型: %d (0=未知, 1=明文DWG, 2=加密DWG)", ctx.content_type);
            DEBUG_LOG("需要解密: %s", ctx.should_decrypt ? "是" : "否");
            DEBUG_LOG("磁盘状态: %s", ctx.disk_encrypted ? "加密" : "明文");
            DEBUG_LOG("内存状态: %s", ctx.in_memory_encrypted ? "加密" : "明文");
            DEBUG_LOG("=======================================");
        } else {
            DEBUG_LOG("普通文件打开: %s (fd=%d)", resolved, fd);
        }
        
        fd_ctx_set(fd, &ctx);
        free(resolved);
    } else if (fd < 0) {
        DEBUG_LOG("openat调用失败: pathname='%s', 错误: %s", pathname ? pathname : "NULL", strerror(errno));
    }
    
    return fd;
}

int open(const char *pathname, int flags, ...) {
    static int (*real_open)(const char *, int, ...) = NULL;
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
        DEBUG_LOG("open Hook已加载: real_open=%p", real_open);
    }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    int fd = (flags & O_CREAT) ? real_open(pathname, flags, mode)
                               : real_open(pathname, flags);
    
    if (fd >= 0 && pathname) {
        DEBUG_LOG("open Hook调用成功: pathname='%s', fd=%d, flags=0x%x", pathname, fd, flags);
        
        char *resolved = realpath(pathname, NULL);
        if (!resolved) resolved = strdup(pathname);
        
        fd_context_t ctx = {0};
        ctx.path = resolved;
        ctx.is_target = is_target_dwg_file(resolved);
        
        if (ctx.is_target) {
            ctx.content_type = check_fd_content_type(fd);
            ctx.should_decrypt = (ctx.content_type == 2);
            ctx.disk_encrypted = (ctx.content_type == 2);
            ctx.in_memory_encrypted = (ctx.content_type == 2);
            
            struct stat st;
            if (fstat(fd, &st) == 0) {
                ctx.file_size = st.st_size;
            }
            
            DEBUG_LOG("=====【成功打开目标DWG文件】=====");
            DEBUG_LOG("文件描述符: %d", fd);
            DEBUG_LOG("绝对路径: %s", resolved);
            DEBUG_LOG("文件大小: %ld 字节", (long)ctx.file_size);
            DEBUG_LOG("内容类型: %d (0=未知, 1=明文DWG, 2=加密DWG)", ctx.content_type);
            DEBUG_LOG("需要解密: %s", ctx.should_decrypt ? "是" : "否");
            DEBUG_LOG("磁盘状态: %s", ctx.disk_encrypted ? "加密" : "明文");
            DEBUG_LOG("内存状态: %s", ctx.in_memory_encrypted ? "加密" : "明文");
            DEBUG_LOG("=======================================");
        } else {
            DEBUG_LOG("普通文件打开: %s (fd=%d)", resolved, fd);
        }
        
        fd_ctx_set(fd, &ctx);
        free(resolved);
    } else if (fd < 0) {
        DEBUG_LOG("open调用失败: pathname='%s', 错误: %s", pathname ? pathname : "NULL", strerror(errno));
    }
    
    return fd;
}

// ==================== Hook：读取时透明解密 ====================

ssize_t pread64(int fd, void *buf, size_t count, off_t offset) {
    static ssize_t (*real_pread64)(int, void *, size_t, off_t) = NULL;
    if (!real_pread64) {
        real_pread64 = dlsym(RTLD_NEXT, "pread64");
        DEBUG_LOG("pread64 Hook已加载: real_pread64=%p", real_pread64);
    }

    ssize_t ret = real_pread64(fd, buf, count, offset);
    if (ret <= 0) return ret;

    fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    if (!fd_ctx_get_copy(fd, &ctx)) return ret;

    if (ctx.is_target && ctx.should_decrypt) {
        DEBUG_LOG("=====【pread64 Hook成功调用】=====");
        DEBUG_LOG("文件: %s", ctx.path ? ctx.path : "未知");
        DEBUG_LOG("读取偏移: %ld, 请求大小: %zd, 实际读取: %zd", (long)offset, count, ret);
        log_hex_3_bytes("解密前数据", (unsigned char *)buf, ret);
        
        xor_encrypt_decrypt((unsigned char *)buf, ret);
        
        log_hex_3_bytes("解密后数据", (unsigned char *)buf, ret);
        DEBUG_LOG("pread64解密成功: fd=%d, 解密字节数: %zd", fd, ret);
        DEBUG_LOG("=====================================");
    } else if (ctx.is_target) {
        DEBUG_LOG("pread64读取明文DWG: fd=%d, 文件=%s, 读取字节=%zd", 
                  fd, ctx.path ? ctx.path : "未知", ret);
    }
    
    free(ctx.path);
    return ret;
}

ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
    static ssize_t (*real_pread)(int, void *, size_t, off_t) = NULL;
    if (!real_pread) {
        real_pread = dlsym(RTLD_NEXT, "pread");
        DEBUG_LOG("pread Hook已加载: real_pread=%p", real_pread);
    }

    ssize_t ret = real_pread(fd, buf, count, offset);
    if (ret <= 0) return ret;

    fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    if (!fd_ctx_get_copy(fd, &ctx)) return ret;

    if (ctx.is_target && ctx.should_decrypt) {
        DEBUG_LOG("=====【pread Hook成功调用】=====");
        DEBUG_LOG("文件: %s", ctx.path ? ctx.path : "未知");
        DEBUG_LOG("读取偏移: %ld, 请求大小: %zd, 实际读取: %zd", (long)offset, count, ret);
        log_hex_3_bytes("解密前数据", (unsigned char *)buf, ret);
        
        xor_encrypt_decrypt((unsigned char *)buf, ret);
        
        log_hex_3_bytes("解密后数据", (unsigned char *)buf, ret);
        DEBUG_LOG("pread解密成功: fd=%d, 解密字节数: %zd", fd, ret);
        DEBUG_LOG("===================================");
    } else if (ctx.is_target) {
        DEBUG_LOG("pread读取明文DWG: fd=%d, 文件=%s, 读取字节=%zd", 
                  fd, ctx.path ? ctx.path : "未知", ret);
    }
    
    free(ctx.path);
    return ret;
}

ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real_read)(int, void *, size_t) = NULL;
    if (!real_read) {
        real_read = dlsym(RTLD_NEXT, "read");
        DEBUG_LOG("read Hook已加载: real_read=%p", real_read);
    }

    ssize_t ret = real_read(fd, buf, count);
    if (ret <= 0) return ret;

    fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    if (!fd_ctx_get_copy(fd, &ctx)) return ret;

    if (ctx.is_target && ctx.should_decrypt) {
        DEBUG_LOG("=====【read Hook成功调用】=====");
        DEBUG_LOG("文件: %s", ctx.path ? ctx.path : "未知");
        DEBUG_LOG("请求大小: %zd, 实际读取: %zd", count, ret);
        log_hex_3_bytes("解密前数据", (unsigned char *)buf, ret);
        
        xor_encrypt_decrypt((unsigned char *)buf, ret);
        
        log_hex_3_bytes("解密后数据", (unsigned char *)buf, ret);
        DEBUG_LOG("read解密成功: fd=%d, 解密字节数: %zd", fd, ret);
        DEBUG_LOG("==================================");
    } else if (ctx.is_target) {
        DEBUG_LOG("read读取明文DWG: fd=%d, 文件=%s, 读取字节=%zd", 
                  fd, ctx.path ? ctx.path : "未知", ret);
    }
    
    free(ctx.path);
    return ret;
}

// ==================== Hook：内存映射 ====================

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    static void *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
    if (!real_mmap) {
        real_mmap = dlsym(RTLD_NEXT, "mmap");
        DEBUG_LOG("mmap Hook已加载: real_mmap=%p", real_mmap);
    }

    void *ptr = real_mmap(addr, length, prot, flags, fd, offset);
    if (ptr == MAP_FAILED) {
        DEBUG_LOG("mmap调用失败: fd=%d, 错误: %s", fd, strerror(errno));
        return ptr;
    }

    int should_decrypt = 0;
    char *file_path = NULL;
    if (fd >= 0) {
        fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
        if (fd_ctx_get_copy(fd, &ctx)) {
            should_decrypt = ctx.should_decrypt ? 1 : 0;
            file_path = ctx.path;
            if (ctx.is_target) {
                DEBUG_LOG("=====【mmap Hook成功调用】=====");
                DEBUG_LOG("文件: %s", file_path ? file_path : "未知");
                DEBUG_LOG("映射地址: %p, 长度: %zu", ptr, length);
                DEBUG_LOG("文件偏移: %ld", (long)offset);
                DEBUG_LOG("需要解密: %s", should_decrypt ? "是" : "否");
                DEBUG_LOG("保护模式: 0x%x", prot);
                DEBUG_LOG("映射标志: 0x%x", flags);
            }
        }
    }

    track_mmap_region(ptr, length, should_decrypt, prot, flags, fd, offset);

    // 如果是目标文件，检查并解密
    if (should_decrypt && (prot & PROT_READ)) {
        if (check_and_decrypt_mmap_region(ptr, length, fd)) {
            DEBUG_LOG("mmap区域解密成功: addr=%p, 长度=%zu", ptr, length);
        } else {
            DEBUG_LOG("mmap区域无需解密或解密失败: addr=%p, 长度=%zu", ptr, length);
        }
        DEBUG_LOG("======================================");
    }
    
    if (file_path) free(file_path);
    return ptr;
}

void *mmap64(void *addr, size_t length, int prot, int flags, int fd, off64_t offset) {
    static void *(*real_mmap64)(void *, size_t, int, int, int, off64_t) = NULL;
    if (!real_mmap64) {
        real_mmap64 = dlsym(RTLD_NEXT, "mmap64");
        DEBUG_LOG("mmap64 Hook已加载: real_mmap64=%p", real_mmap64);
    }

    void *ptr = real_mmap64(addr, length, prot, flags, fd, offset);
    if (ptr == MAP_FAILED) {
        DEBUG_LOG("mmap64调用失败: fd=%d, 错误: %s", fd, strerror(errno));
        return ptr;
    }

    int should_decrypt = 0;
    char *file_path = NULL;
    if (fd >= 0) {
        fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
        if (fd_ctx_get_copy(fd, &ctx)) {
            should_decrypt = ctx.should_decrypt ? 1 : 0;
            file_path = ctx.path;
            if (ctx.is_target) {
                DEBUG_LOG("=====【mmap64 Hook成功调用】=====");
                DEBUG_LOG("文件: %s", file_path ? file_path : "未知");
                DEBUG_LOG("映射地址: %p, 长度: %zu", ptr, length);
                DEBUG_LOG("文件偏移: %ld", (long)offset);
                DEBUG_LOG("需要解密: %s", should_decrypt ? "是" : "否");
                DEBUG_LOG("保护模式: 0x%x", prot);
                DEBUG_LOG("映射标志: 0x%x", flags);
            }
        }
    }

    track_mmap_region(ptr, length, should_decrypt, prot, flags, fd, (off_t)offset);

    if (should_decrypt && (prot & PROT_READ)) {
        if (check_and_decrypt_mmap_region(ptr, length, fd)) {
            DEBUG_LOG("mmap64区域解密成功: addr=%p, 长度=%zu", ptr, length);
        } else {
            DEBUG_LOG("mmap64区域无需解密或解密失败: addr=%p, 长度=%zu", ptr, length);
        }
        DEBUG_LOG("========================================");
    }
    
    if (file_path) free(file_path);
    return ptr;
}

int munmap(void *addr, size_t length) {
    static int (*real_munmap)(void *, size_t) = NULL;
    if (!real_munmap) {
        real_munmap = dlsym(RTLD_NEXT, "munmap");
        DEBUG_LOG("munmap Hook已加载: real_munmap=%p", real_munmap);
    }

    // 检查是否需要在解除映射前加密
    mmap_region_t *region = find_mmap_region(addr);
    if (region && region->should_decrypt && region->modified) {
        DEBUG_LOG("munmap前需要加密内存区域 %p+%zu", addr, length);
        // 这里可以添加加密逻辑，确保磁盘上保存的是密文
    }

    int ret = real_munmap(addr, length);
    if (ret == 0) {
        DEBUG_LOG("munmap成功: addr=%p, 长度=%zu", addr, length);
        untrack_mmap_region(addr);
    } else {
        DEBUG_LOG("munmap失败: addr=%p, 长度=%zu, 错误: %s", addr, length, strerror(errno));
    }
    return ret;
}

// ==================== Hook：写入时加密 ====================

ssize_t write(int fd, const void *buf, size_t count) {
    static ssize_t (*real_write)(int, const void *, size_t) = NULL;
    if (!real_write) {
        real_write = dlsym(RTLD_NEXT, "write");
        DEBUG_LOG("write Hook已加载: real_write=%p", real_write);
    }

    if (count == 0 || !buf) return real_write(fd, buf, count);

    fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    if (!fd_ctx_get_copy(fd, &ctx)) return real_write(fd, buf, count);

    ssize_t ret;
    if (!ctx.is_target) {
        ret = real_write(fd, buf, count);
    } else {
        // 目标文件：加密后写入
        DEBUG_LOG("=====【write Hook成功调用】=====");
        DEBUG_LOG("文件: %s", ctx.path ? ctx.path : "未知");
        DEBUG_LOG("写入大小: %zd", count);
        log_hex_3_bytes("加密前数据", (unsigned char *)buf, count);
        
        void *tmp = malloc(count);
        if (!tmp) { 
            free(ctx.path); 
            errno = ENOMEM; 
            DEBUG_LOG("write内存分配失败");
            return -1; 
        }
        memcpy(tmp, buf, count);
        xor_encrypt_decrypt((unsigned char *)tmp, count);
        
        log_hex_3_bytes("加密后数据", (unsigned char *)tmp, count);

        ret = real_write(fd, tmp, count);
        free(tmp);
        
        if (ret >= 0) {
            DEBUG_LOG("write加密写入成功: fd=%d, 请求=%zd字节, 实际写入=%zd字节", fd, count, ret);
            bool dk = true;
            fd_ctx_update_flags(fd, &dk, NULL);
        } else {
            DEBUG_LOG("write写入失败: fd=%d, 错误: %s", fd, strerror(errno));
        }
        DEBUG_LOG("====================================");
    }
    free(ctx.path);
    return ret;
}

ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset) {
    static ssize_t (*real_pwrite64)(int, const void *, size_t, off_t) = NULL;
    if (!real_pwrite64) {
        real_pwrite64 = dlsym(RTLD_NEXT, "pwrite64");
        DEBUG_LOG("pwrite64 Hook已加载: real_pwrite64=%p", real_pwrite64);
    }

    if (count == 0 || !buf) return real_pwrite64(fd, buf, count, offset);

    fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    if (!fd_ctx_get_copy(fd, &ctx)) return real_pwrite64(fd, buf, count, offset);

    ssize_t ret;
    if (!ctx.is_target) {
        ret = real_pwrite64(fd, buf, count, offset);
    } else {
        DEBUG_LOG("=====【pwrite64 Hook成功调用】=====");
        DEBUG_LOG("文件: %s", ctx.path ? ctx.path : "未知");
        DEBUG_LOG("写入偏移: %ld, 大小: %zd", (long)offset, count);
        log_hex_3_bytes("加密前数据", (unsigned char *)buf, count);
        
        void *tmp = malloc(count);
        if (!tmp) { 
            free(ctx.path); 
            errno = ENOMEM; 
            DEBUG_LOG("pwrite64内存分配失败");
            return -1; 
        }
        memcpy(tmp, buf, count);
        xor_encrypt_decrypt((unsigned char *)tmp, count);
        
        log_hex_3_bytes("加密后数据", (unsigned char *)tmp, count);

        ret = real_pwrite64(fd, tmp, count, offset);
        free(tmp);
        
        if (ret >= 0) {
            DEBUG_LOG("pwrite64加密写入成功: fd=%d, 请求=%zd字节, 实际写入=%zd字节", fd, count, ret);
            bool dk = true;
            fd_ctx_update_flags(fd, &dk, NULL);
        } else {
            DEBUG_LOG("pwrite64写入失败: fd=%d, 错误: %s", fd, strerror(errno));
        }
        DEBUG_LOG("=======================================");
    }
    free(ctx.path);
    return ret;
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
    static ssize_t (*real_pwrite)(int, const void *, size_t, off_t) = NULL;
    if (!real_pwrite) {
        real_pwrite = dlsym(RTLD_NEXT, "pwrite");
        DEBUG_LOG("pwrite Hook已加载: real_pwrite=%p", real_pwrite);
    }

    if (count == 0 || !buf) return real_pwrite(fd, buf, count, offset);

    fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    if (!fd_ctx_get_copy(fd, &ctx)) return real_pwrite(fd, buf, count, offset);

    ssize_t ret;
    if (!ctx.is_target) {
        ret = real_pwrite(fd, buf, count, offset);
    } else {
        DEBUG_LOG("=====【pwrite Hook成功调用】=====");
        DEBUG_LOG("文件: %s", ctx.path ? ctx.path : "未知");
        DEBUG_LOG("写入偏移: %ld, 大小: %zd", (long)offset, count);
        log_hex_3_bytes("加密前数据", (unsigned char *)buf, count);
        
        void *tmp = malloc(count);
        if (!tmp) { 
            free(ctx.path); 
            errno = ENOMEM; 
            DEBUG_LOG("pwrite内存分配失败");
            return -1; 
        }
        memcpy(tmp, buf, count);
        xor_encrypt_decrypt((unsigned char *)tmp, count);
        
        log_hex_3_bytes("加密后数据", (unsigned char *)tmp, count);

        ret = real_pwrite(fd, tmp, count, offset);
        free(tmp);
        
        if (ret >= 0) {
            DEBUG_LOG("pwrite加密写入成功: fd=%d, 请求=%zd字节, 实际写入=%zd字节", fd, count, ret);
            bool dk = true;
            fd_ctx_update_flags(fd, &dk, NULL);
        } else {
            DEBUG_LOG("pwrite写入失败: fd=%d, 错误: %s", fd, strerror(errno));
        }
        DEBUG_LOG("=====================================");
    }
    free(ctx.path);
    return ret;
}

// ==================== Hook：文件重命名 ====================

int rename(const char *oldpath, const char *newpath) {
    static int (*real_rename)(const char *, const char *) = NULL;
    if (!real_rename) {
        real_rename = dlsym(RTLD_NEXT, "rename");
        DEBUG_LOG("rename Hook已加载: real_rename=%p", real_rename);
    }

    if (oldpath && newpath) {
        DEBUG_LOG("rename操作: '%s' -> '%s'", oldpath, newpath);
        
        // 检查是否涉及DWG文件
        int old_is_dwg = is_target_dwg_file(oldpath);
        int new_is_dwg = is_target_dwg_file(newpath);
        
        if (old_is_dwg || new_is_dwg) {
            DEBUG_LOG("DWG文件重命名: old_is_dwg=%d new_is_dwg=%d", old_is_dwg, new_is_dwg);
        }
    }

    int ret = real_rename(oldpath, newpath);
    if (ret == 0) {
        DEBUG_LOG("rename成功");
    } else {
        DEBUG_LOG("rename失败: %s", strerror(errno));
    }
    
    return ret;
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    static int (*real_renameat)(int, const char *, int, const char *) = NULL;
    if (!real_renameat) {
        real_renameat = dlsym(RTLD_NEXT, "renameat");
        DEBUG_LOG("renameat Hook已加载: real_renameat=%p", real_renameat);
    }

    if (oldpath && newpath) {
        DEBUG_LOG("renameat操作: '%s' -> '%s'", oldpath, newpath);
    }

    int ret = real_renameat(olddirfd, oldpath, newdirfd, newpath);
    if (ret == 0) {
        DEBUG_LOG("renameat成功");
    } else {
        DEBUG_LOG("renameat失败: %s", strerror(errno));
    }
    
    return ret;
}

// ==================== Hook：关闭文件 ====================

int close(int fd) {
    static int (*real_close)(int) = NULL;
    if (!real_close) {
        real_close = dlsym(RTLD_NEXT, "close");
        DEBUG_LOG("close Hook已加载: real_close=%p", real_close);
    }

    // 获取上下文用于日志
    fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    int have_ctx = fd_ctx_get_copy(fd, &ctx);

    int ret = real_close(fd);
    if (ret == 0) {
        if (have_ctx && ctx.is_target) {
            DEBUG_LOG("=====【成功关闭目标DWG文件】=====");
            DEBUG_LOG("文件描述符: %d", fd);
            DEBUG_LOG("绝对路径: %s", ctx.path ? ctx.path : "未知");
            DEBUG_LOG("内容类型: %d", ctx.content_type);
            DEBUG_LOG("最终磁盘状态: %s", ctx.disk_encrypted ? "加密" : "明文");
            DEBUG_LOG("=====================================");
        }
        fd_ctx_remove(fd);
    } else {
        DEBUG_LOG("close失败: fd=%d, 错误: %s", fd, strerror(errno));
    }
    
    if (have_ctx) free(ctx.path);
    return ret;
}

// ==================== Hook：其他可能的文件访问方式 ====================

// Hook fopen系列函数
FILE *fopen(const char *pathname, const char *mode) {
    static FILE *(*real_fopen)(const char *, const char *) = NULL;
    if (!real_fopen) {
        real_fopen = dlsym(RTLD_NEXT, "fopen");
        DEBUG_LOG("fopen Hook已加载: real_fopen=%p", real_fopen);
    }
    
    FILE *fp = real_fopen(pathname, mode);
    if (fp && pathname && is_target_dwg_file(pathname)) {
        int fd = fileno(fp);
        if (fd >= 0) {
            DEBUG_LOG("=====【fopen Hook成功调用】=====");
            DEBUG_LOG("目标DWG文件: path='%s', mode='%s', fd=%d", pathname, mode, fd);
            
            fd_context_t ctx = {0};
            ctx.path = realpath(pathname, NULL);
            if (!ctx.path) ctx.path = strdup(pathname);
            ctx.is_target = 1;
            ctx.content_type = check_fd_content_type(fd);
            ctx.should_decrypt = (ctx.content_type == 2);
            ctx.disk_encrypted = (ctx.content_type == 2);
            ctx.in_memory_encrypted = (ctx.content_type == 2);
            
            fd_ctx_set(fd, &ctx);
            DEBUG_LOG("fopen处理完成: 内容类型=%d, 需要解密=%s", 
                      ctx.content_type, ctx.should_decrypt ? "是" : "否");
            DEBUG_LOG("====================================");
            free(ctx.path);
        }
    } else if (!fp) {
        DEBUG_LOG("fopen失败: pathname='%s', 错误: %s", pathname ? pathname : "NULL", strerror(errno));
    }
    
    return fp;
}

FILE *fopen64(const char *pathname, const char *mode) {
    static FILE *(*real_fopen64)(const char *, const char *) = NULL;
    if (!real_fopen64) {
        real_fopen64 = dlsym(RTLD_NEXT, "fopen64");
        DEBUG_LOG("fopen64 Hook已加载: real_fopen64=%p", real_fopen64);
    }
    
    FILE *fp = real_fopen64(pathname, mode);
    if (fp && pathname && is_target_dwg_file(pathname)) {
        int fd = fileno(fp);
        if (fd >= 0) {
            DEBUG_LOG("=====【fopen64 Hook成功调用】=====");
            DEBUG_LOG("目标DWG文件: path='%s', mode='%s', fd=%d", pathname, mode, fd);
            
            fd_context_t ctx = {0};
            ctx.path = realpath(pathname, NULL);
            if (!ctx.path) ctx.path = strdup(pathname);
            ctx.is_target = 1;
            ctx.content_type = check_fd_content_type(fd);
            ctx.should_decrypt = (ctx.content_type == 2);
            ctx.disk_encrypted = (ctx.content_type == 2);
            ctx.in_memory_encrypted = (ctx.content_type == 2);
            
            fd_ctx_set(fd, &ctx);
            DEBUG_LOG("fopen64处理完成: 内容类型=%d, 需要解密=%s", 
                      ctx.content_type, ctx.should_decrypt ? "是" : "否");
            DEBUG_LOG("======================================");
            free(ctx.path);
        }
    } else if (!fp) {
        DEBUG_LOG("fopen64失败: pathname='%s', 错误: %s", pathname ? pathname : "NULL", strerror(errno));
    }
    
    return fp;
}

// Hook fread函数
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    static size_t (*real_fread)(void *, size_t, size_t, FILE *) = NULL;
    if (!real_fread) {
        real_fread = dlsym(RTLD_NEXT, "fread");
        DEBUG_LOG("fread Hook已加载: real_fread=%p", real_fread);
    }
    
    size_t ret = real_fread(ptr, size, nmemb, stream);
    if (ret > 0 && stream) {
        int fd = fileno(stream);
        if (fd >= 0) {
            fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
            if (fd_ctx_get_copy(fd, &ctx)) {
                if (ctx.is_target && ctx.should_decrypt) {
                    size_t total_bytes = ret * size;
                    DEBUG_LOG("=====【fread Hook成功调用】=====");
                    DEBUG_LOG("文件: %s", ctx.path ? ctx.path : "未知");
                    DEBUG_LOG("读取大小: %zd字节", total_bytes);
                    log_hex_3_bytes("fread解密前数据", (unsigned char *)ptr, total_bytes);
                    
                    xor_encrypt_decrypt((unsigned char *)ptr, total_bytes);
                    
                    log_hex_3_bytes("fread解密后数据", (unsigned char *)ptr, total_bytes);
                    DEBUG_LOG("fread解密成功: fd=%d, 解密字节数=%zd", fd, total_bytes);
                    DEBUG_LOG("====================================");
                } else if (ctx.is_target) {
                    size_t total_bytes = ret * size;
                    DEBUG_LOG("fread读取明文DWG: fd=%d, 文件=%s, 读取字节=%zd", 
                              fd, ctx.path ? ctx.path : "未知", total_bytes);
                }
                free(ctx.path);
            }
        }
    }
    
    return ret;
}

// Hook fwrite函数
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    static size_t (*real_fwrite)(const void *, size_t, size_t, FILE *) = NULL;
    if (!real_fwrite) {
        real_fwrite = dlsym(RTLD_NEXT, "fwrite");
        DEBUG_LOG("fwrite Hook已加载: real_fwrite=%p", real_fwrite);
    }
    
    if (!stream || !ptr || size == 0 || nmemb == 0) {
        return real_fwrite(ptr, size, nmemb, stream);
    }
    
    int fd = fileno(stream);
    if (fd >= 0) {
        fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
        if (fd_ctx_get_copy(fd, &ctx)) {
            if (ctx.is_target) {
                // 加密后写入
                size_t total_bytes = size * nmemb;
                DEBUG_LOG("=====【fwrite Hook成功调用】=====");
                DEBUG_LOG("文件: %s", ctx.path ? ctx.path : "未知");
                DEBUG_LOG("写入大小: %zd", total_bytes);
                log_hex_3_bytes("fwrite加密前数据", (unsigned char *)ptr, total_bytes);
                
                void *tmp = malloc(total_bytes);
                if (!tmp) {
                    free(ctx.path);
                    errno = ENOMEM;
                    DEBUG_LOG("fwrite内存分配失败");
                    return 0;
                }
                memcpy(tmp, ptr, total_bytes);
                xor_encrypt_decrypt((unsigned char *)tmp, total_bytes);
                
                log_hex_3_bytes("fwrite加密后数据", (unsigned char *)tmp, total_bytes);
                
                size_t result = real_fwrite(tmp, size, nmemb, stream);
                free(tmp);
                
                if (result > 0) {
                    DEBUG_LOG("fwrite加密写入成功: fd=%d, 请求=%zd字节, 实际写入=%zd个元素", 
                              fd, total_bytes, result);
                } else {
                    DEBUG_LOG("fwrite写入失败: fd=%d, 错误: %s", fd, strerror(errno));
                }
                DEBUG_LOG("======================================");
                free(ctx.path);
                return result;
            }
            free(ctx.path);
        }
    }
    
    return real_fwrite(ptr, size, nmemb, stream);
}

// ==================== 库初始化 ====================

__attribute__((constructor))
static void init_dwg_hook(void) {
    // 设置UTF-8环境
    setlocale(LC_ALL, "zh_CN.UTF-8");
    
    // 清空日志文件并写入UTF-8 BOM
    FILE *logfp = fopen(LOG_FILE_PATH, "w");
    if (logfp) {
        // 写入UTF-8 BOM确保中文正常显示
        unsigned char bom[] = {0xEF, 0xBB, 0xBF};
        fwrite(bom, 1, 3, logfp);
        fclose(logfp);
    }
    
    DEBUG_LOG("=====【DWG透明加解密Hook库启动】=====");
    DEBUG_LOG("目标: 所有.dwg文件的透明加解密");
    DEBUG_LOG("算法: XOR 0xFF");
    DEBUG_LOG("日志文件: %s", LOG_FILE_PATH);
    DEBUG_LOG("编码: UTF-8 (支持中文)");
    DEBUG_LOG("使用方法: export DWG_HOOK_DEBUG=1");
    DEBUG_LOG("注入方法: LD_PRELOAD=/home/chane/tif_crypto_hook/libdwg_hook_improved.so ./ZWCAD \"$@\" /product ZWCAD");
    DEBUG_LOG("特性: 移除'changed_'路径限制，支持所有DWG文件");
    DEBUG_LOG("Hook加载状态: 所有函数Hook已准备就绪");
    DEBUG_LOG("=========================================");
}

__attribute__((destructor))
static void cleanup_dwg_hook(void) {
    DEBUG_LOG("=====【DWG透明加解密Hook库卸载】=====");
    DEBUG_LOG("清理所有资源...");
    DEBUG_LOG("Hook库已安全卸载");
    DEBUG_LOG("=====================================");
}