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

// 文件路径: /home/chane/tif_crypto_hook/dwg_hook_test.c

// 编译命令:
//   gcc -shared -fPIC -o libdwg_hook.so dwg_hook_test.c -ldl -lpthread

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
#include <strings.h> // 用于strcasecmp

// ==================== 配置选项 ====================
#define MAX_TRACKED_FD 1024        // 最大跟踪文件描述符数量
#define MAX_MMAP_REGIONS 256       // 最大跟踪内存映射区域数量
#define HOT_PATH_CACHE_SIZE 32     // 热点路径缓存大小
#define DEBUG_LOG_ENABLED 1         // 是否启用调试日志
#define DECRYPT_THRESHOLD 10        // 解密访问阈值

// ==================== 调试日志系统 ====================
#define DEBUG_LOG(fmt, ...) \
    do { \
        if (DEBUG_LOG_ENABLED) { \
            FILE *logfp = fopen("/tmp/dwg_hook.log", "a"); \
            if (logfp) { \
                fprintf(logfp, "[DWG透明加密] %s:%d " fmt "\n", \
                        __func__, __LINE__, ##__VA_ARGS__); \
                fclose(logfp); \
            } \
        } \
    } while (0)

// ==================== 数据结构定义 ====================

// FD上下文结构：跟踪文件描述符相关信息
typedef struct {
    int fd;                     // 文件描述符
    char *path;                 // 文件完整路径
    ino_t inode;                // 文件inode号
    dev_t device;               // 文件所在设备号
    bool is_target;             // 是否为目标DWG文件
    time_t last_verified;       // 最后验证时间戳
    int access_count;           // 访问计数器
    struct fd_context *next;    // 哈希冲突链表指针
} fd_context_t;

// 内存映射区域跟踪结构
typedef struct {
    void *addr;                 // 映射起始地址
    size_t length;              // 映射长度
    int prot;                   // 内存保护权限
    int flags;                  // 映射标志
    int fd;                     // 关联的文件描述符
    off_t offset;               // 文件偏移量
    bool modified;              // 是否被修改过
    bool in_mem_encrypted;      // 内存中是否加密
    bool disk_encrypted;        // 磁盘上是否加密
    struct mmap_region *next;   // 关联到同一fd的下一个区域
} mmap_region_t;

// 热点路径缓存项
typedef struct {
    dev_t device;               // 设备号
    ino_t inode;                // inode号
    char path[PATH_MAX];        // 文件路径
    time_t last_used;           // 最后使用时间
} hot_path_cache_t;

// ==================== 全局变量 ====================
static fd_context_t *fd_context_table[MAX_TRACKED_FD] = {0};  // FD上下文哈希表
static pthread_rwlock_t fd_table_lock = PTHREAD_RWLOCK_INITIALIZER; // FD表读写锁
static mmap_region_t mmap_regions[MAX_MMAP_REGIONS] = {0};    // 内存映射区域数组
static pthread_mutex_t mmap_mutex = PTHREAD_MUTEX_INITIALIZER; // 内存映射互斥锁
static hot_path_cache_t hot_path_cache[HOT_PATH_CACHE_SIZE] = {0}; // 热点路径缓存
static pthread_mutex_t hot_path_mutex = PTHREAD_MUTEX_INITIALIZER; // 缓存互斥锁

// ==================== FD上下文管理 ====================

/**
 * 初始化FD上下文
 * @param fd 文件描述符
 * @param path 文件路径
 */
static void init_fd_context(int fd, const char *path) {
    if (fd < 0 || fd >= MAX_TRACKED_FD || !path) {
        DEBUG_LOG("无效参数: fd=%d, path=%p", fd, path);
        return;
    }
    
    struct stat st;
    if (fstat(fd, &st) != 0) {
        DEBUG_LOG("fstat失败 fd=%d: %s", fd, strerror(errno));
        return;
    }

    // 分配并初始化上下文
    fd_context_t *ctx = malloc(sizeof(fd_context_t));
    if (!ctx) {
        DEBUG_LOG("内存分配失败 fd=%d", fd);
        return;
    }
    
    ctx->fd = fd;
    ctx->path = realpath(path, NULL); // 获取绝对路径
    if (!ctx->path) {
        ctx->path = strdup(path); // 回退到原始路径
        DEBUG_LOG("realpath失败, 使用原始路径: %s", path);
    }
    ctx->inode = st.st_ino;
    ctx->device = st.st_dev;
    ctx->is_target = is_target_dwg_file(ctx->path);
    ctx->last_verified = time(NULL);
    ctx->access_count = 0;
    ctx->next = NULL;

    // 添加到哈希表
    int slot = fd % MAX_TRACKED_FD;
    pthread_rwlock_wrlock(&fd_table_lock);
    
    if (fd_context_table[slot] == NULL) {
        fd_context_table[slot] = ctx;
    } else {
        // 添加到链表尾部
        fd_context_t *current = fd_context_table[slot];
        while (current->next) {
            current = current->next;
        }
        current->next = ctx;
    }
    
    pthread_rwlock_unlock(&fd_table_lock);
    
    DEBUG_LOG("FD上下文初始化: fd=%d, 路径=%s, inode=%lu, 目标文件=%d", 
             fd, ctx->path, ctx->inode, ctx->is_target);
}

/**
 * 获取FD上下文
 * @param fd 文件描述符
 * @return 上下文指针或NULL
 */
static fd_context_t *get_fd_context(int fd) {
    if (fd < 0 || fd >= MAX_TRACKED_FD) {
        return NULL;
    }
    
    int slot = fd % MAX_TRACKED_FD;
    fd_context_t *ctx = NULL;
    
    // 获取读锁
    pthread_rwlock_rdlock(&fd_table_lock);
    ctx = fd_context_table[slot];
    
    // 遍历链表查找匹配的fd
    while (ctx) {
        if (ctx->fd == fd) {
            break;
        }
        ctx = ctx->next;
    }
    
    pthread_rwlock_unlock(&fd_table_lock);
    return ctx;
}

/**
 * 更新FD上下文（如果需要）
 * @param ctx FD上下文指针
 */
static void update_fd_context(fd_context_t *ctx) {
    if (!ctx) return;
    
    // 检查是否需要重新验证（每10次访问或超过5秒）
    time_t now = time(NULL);
    if (ctx->access_count++ < DECRYPT_THRESHOLD && 
        (now - ctx->last_verified) < 5) {
        return;
    }
    
    struct stat st;
    if (fstat(ctx->fd, &st) != 0) {
        DEBUG_LOG("fstat失败 fd=%d: %s", ctx->fd, strerror(errno));
        return;
    }

    // 检查元数据是否变化
    if (ctx->inode == st.st_ino && ctx->device == st.st_dev) {
        ctx->last_verified = now;
        return;
    }

    // 元数据变化，需要更新路径
    char proc_path[32];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", ctx->fd);
    
    char buf[PATH_MAX];
    ssize_t len = readlink(proc_path, buf, sizeof(buf)-1);
    if (len > 0) {
        buf[len] = '\0';
        
        // 更新上下文
        free(ctx->path);
        ctx->path = strdup(buf);
        ctx->inode = st.st_ino;
        ctx->device = st.st_dev;
        ctx->is_target = is_target_dwg_file(ctx->path);
        ctx->last_verified = now;
        ctx->access_count = 0;
        
        DEBUG_LOG("FD上下文更新: fd=%d, 新路径=%s, inode=%lu, 目标文件=%d", 
                 ctx->fd, ctx->path, ctx->inode, ctx->is_target);
    } else {
        DEBUG_LOG("readlink失败: %s", strerror(errno));
    }
}

/**
 * 释放FD上下文
 * @param fd 文件描述符
 */
static void release_fd_context(int fd) {
    if (fd < 0 || fd >= MAX_TRACKED_FD) return;
    
    int slot = fd % MAX_TRACKED_FD;
    
    // 获取写锁
    pthread_rwlock_wrlock(&fd_table_lock);
    
    fd_context_t **prev = &fd_context_table[slot];
    fd_context_t *current = fd_context_table[slot];
    
    // 遍历链表查找并移除
    while (current) {
        if (current->fd == fd) {
            *prev = current->next;
            
            // 清理资源
            free(current->path);
            free(current);
            
            DEBUG_LOG("FD上下文释放: fd=%d", fd);
            break;
        }
        prev = &current->next;
        current = current->next;
    }
    
    pthread_rwlock_unlock(&fd_table_lock);
}

// ==================== 热点路径缓存 ====================

/**
 * 添加路径到热点缓存
 * @param path 文件路径
 * @param device 设备号
 * @param inode inode号
 */
static void add_hot_path(const char *path, dev_t device, ino_t inode) {
    if (!path) return;
    
    pthread_mutex_lock(&hot_path_mutex);
    
    // 查找最旧或空槽位
    int oldest_index = 0;
    time_t oldest_time = time(NULL);
    
    for (int i = 0; i < HOT_PATH_CACHE_SIZE; i++) {
        if (hot_path_cache[i].device == 0) {
            oldest_index = i;
            break;
        }
        if (hot_path_cache[i].last_used < oldest_time) {
            oldest_time = hot_path_cache[i].last_used;
            oldest_index = i;
        }
    }
    
    // 更新缓存项
    hot_path_cache[oldest_index].device = device;
    hot_path_cache[oldest_index].inode = inode;
    strncpy(hot_path_cache[oldest_index].path, path, PATH_MAX-1);
    hot_path_cache[oldest_index].path[PATH_MAX-1] = '\0';
    hot_path_cache[oldest_index].last_used = time(NULL);
    
    pthread_mutex_unlock(&hot_path_mutex);
    
    DEBUG_LOG("热点路径缓存添加: %s (dev=%lu, inode=%lu)", 
             path, (unsigned long)device, (unsigned long)inode);
}

/**
 * 从热点缓存获取路径
 * @param device 设备号
 * @param inode inode号
 * @return 文件路径或NULL
 */
static const char *get_hot_path(dev_t device, ino_t inode) {
    pthread_mutex_lock(&hot_path_mutex);
    
    for (int i = 0; i < HOT_PATH_CACHE_SIZE; i++) {
        if (hot_path_cache[i].device == device && 
            hot_path_cache[i].inode == inode) {
            // 更新最后使用时间
            hot_path_cache[i].last_used = time(NULL);
            const char *path = hot_path_cache[i].path;
            pthread_mutex_unlock(&hot_path_mutex);
            return path;
        }
    }
    
    pthread_mutex_unlock(&hot_path_mutex);
    return NULL;
}

// ==================== 内存映射管理 ====================

/**
 * 查找空闲内存映射槽位
 * @return 空闲槽位索引或-1
 */
static int find_free_mmap_slot() {
    pthread_mutex_lock(&mmap_mutex);
    
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == NULL) {
            pthread_mutex_unlock(&mmap_mutex);
            return i;
        }
    }
    
    pthread_mutex_unlock(&mmap_mutex);
    return -1;
}

/**
 * 添加内存映射区域
 * @param addr 映射起始地址
 * @param length 映射长度
 * @param prot 保护权限
 * @param flags 映射标志
 * @param fd 文件描述符
 * @param offset 文件偏移
 * @param is_target 是否目标文件
 */
static void add_mmap_region(void *addr, size_t length, int prot, int flags, 
                            int fd, off_t offset, bool is_target) {
    int slot = find_free_mmap_slot();
    if (slot < 0) {
        DEBUG_LOG("添加内存映射区域失败: 无空闲槽位");
        return;
    }
    
    pthread_mutex_lock(&mmap_mutex);
    
    // 初始化映射区域信息
    mmap_regions[slot].addr = addr;
    mmap_regions[slot].length = length;
    mmap_regions[slot].prot = prot;
    mmap_regions[slot].flags = flags;
    mmap_regions[slot].fd = fd;
    mmap_regions[slot].offset = offset;
    mmap_regions[slot].modified = false;
    mmap_regions[slot].in_mem_encrypted = !is_target; // 非目标文件视为已加密
    mmap_regions[slot].disk_encrypted = !is_target;
    mmap_regions[slot].next = NULL;
    
    // 关联到FD上下文
    fd_context_t *ctx = get_fd_context(fd);
    if (ctx) {
        // 添加到FD关联的映射列表
        mmap_region_t *current = (mmap_region_t *)ctx->next;
        if (!current) {
            ctx->next = (fd_context_t *)&mmap_regions[slot];
        } else {
            while (current->next) {
                current = current->next;
            }
            current->next = &mmap_regions[slot];
        }
    }
    
    pthread_mutex_unlock(&mmap_mutex);
    
    DEBUG_LOG("内存映射区域添加: slot=%d, 地址=%p, 长度=%zu, fd=%d, 目标文件=%d", 
             slot, addr, length, fd, is_target);
}

/**
 * 移除内存映射区域
 * @param addr 映射起始地址
 */
static void remove_mmap_region(void *addr) {
    pthread_mutex_lock(&mmap_mutex);
    
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == addr) {
            // 从FD关联列表中移除
            fd_context_t *ctx = get_fd_context(mmap_regions[i].fd);
            if (ctx) {
                mmap_region_t **prev = (mmap_region_t **)&ctx->next;
                mmap_region_t *current = (mmap_region_t *)ctx->next;
                
                while (current) {
                    if (current == &mmap_regions[i]) {
                        *prev = current->next;
                        break;
                    }
                    prev = &current->next;
                    current = current->next;
                }
            }
            
            // 清除区域信息
            mmap_regions[i].addr = NULL;
            DEBUG_LOG("内存映射区域移除: 地址=%p", addr);
            break;
        }
    }
    
    pthread_mutex_unlock(&mmap_mutex);
}

// ==================== 辅助函数 ====================

/**
 * 判断是否为需要处理的目标DWG文件
 * @param path 文件路径
 * @return 1是目标文件，0不是
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
    
    // 检查文件扩展名
    const char *ext = path + len - 4;
    if (strcasecmp(ext, ".dwg") != 0) {
        DEBUG_LOG("文件不是.dwg格式: %s", path);
        return 0;
    }

    // 检查路径中是否包含特定标识
    if (strstr(path, "changed_") == NULL) {
        DEBUG_LOG("文件路径不包含'changed_': %s", path);
        return 0;
    }

    DEBUG_LOG("目标DWG文件已识别: %s", path);
    return 1;
}

/**
 * 安全解密内存映射区域
 * @param addr 起始地址
 * @param length 长度
 * @return 0成功，-1失败
 */
static int safe_decrypt_mmap_region(void *addr, size_t length) {
    if (!addr || length == 0) {
        DEBUG_LOG("无效参数");
        return -1;
    }

    // 临时修改内存权限为可写
    if (mprotect(addr, length, PROT_READ | PROT_WRITE) != 0) {
        DEBUG_LOG("mprotect失败: %s", strerror(errno));
        return -1;
    }

    // 执行异或解密
    unsigned char *data = (unsigned char *)addr;
    for (size_t i = 0; i < length; ++i) {
        data[i] ^= 0xFF;
    }

    DEBUG_LOG("内存解密完成: %p+%zu (前3字节: %02x %02x %02x)",
              addr, length, data[0], data[1], data[2]);

    // 恢复原始权限（简化处理，实际需要记录原始权限）
    mprotect(addr, length, PROT_READ);
    return 0;
}

/**
 * 安全加密内存映射区域
 * @param addr 起始地址
 * @param length 长度
 * @return 0成功，-1失败
 */
static int safe_encrypt_mmap_region(void *addr, size_t length) {
    if (!addr || length == 0) {
        DEBUG_LOG("无效参数");
        return -1;
    }

    // 临时修改内存权限为可写
    if (mprotect(addr, length, PROT_READ | PROT_WRITE) != 0) {
        DEBUG_LOG("mprotect失败: %s", strerror(errno));
        return -1;
    }

    // 执行异或加密
    unsigned char *data = (unsigned char *)addr;
    for (size_t i = 0; i < length; ++i) {
        data[i] ^= 0xFF;
    }

    DEBUG_LOG("内存加密完成: %p+%zu (前3字节: %02x %02x %02x)",
              addr, length, data[0], data[1], data[2]);

    // 恢复原始权限
    mprotect(addr, length, PROT_READ);
    return 0;
}

// ==================== 钩子函数实现 ====================

/**
 * open钩子函数
 */
int open(const char *pathname, int flags, ...) {
    static int (*real_open)(const char *, int, ...) = NULL;
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");
    
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }
    
    DEBUG_LOG("调用open: 路径=%s, 标志=0x%x, 模式=0%o", 
             pathname ? pathname : "(null)", flags, mode);
    
    int fd = (flags & O_CREAT) ? 
        real_open(pathname, flags, mode) : 
        real_open(pathname, flags);
    
    if (fd >= 0) {
        init_fd_context(fd, pathname);
        add_hot_path(pathname, 0, 0);
        DEBUG_LOG("文件打开成功: fd=%d", fd);
    } else {
        DEBUG_LOG("文件打开失败: %s", strerror(errno));
    }
    
    return fd;
}

/**
 * openat钩子函数
 */
int openat(int dirfd, const char *pathname, int flags, ...) {
    static int (*real_openat)(int, const char *, int, ...) = NULL;
    if (!real_openat) real_openat = dlsym(RTLD_NEXT, "openat");
    
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }
    
    DEBUG_LOG("调用openat: 目录fd=%d, 路径=%s, 标志=0x%x, 模式=0%o", 
             dirfd, pathname ? pathname : "(null)", flags, mode);
    
    int fd = (flags & O_CREAT) ? 
        real_openat(dirfd, pathname, flags, mode) : 
        real_openat(dirfd, pathname, flags);
    
    if (fd >= 0) {
        init_fd_context(fd, pathname);
        add_hot_path(pathname, 0, 0);
        DEBUG_LOG("文件打开成功: fd=%d", fd);
    } else {
        DEBUG_LOG("文件打开失败: %s", strerror(errno));
    }
    
    return fd;
}

/**
 * close钩子函数
 */
int close(int fd) {
    static int (*real_close)(int) = NULL;
    if (!real_close) real_close = dlsym(RTLD_NEXT, "close");
    
    DEBUG_LOG("调用close: fd=%d", fd);
    
    release_fd_context(fd);
    int ret = real_close(fd);
    
    if (ret == 0) {
        DEBUG_LOG("文件关闭成功: fd=%d", fd);
    } else {
        DEBUG_LOG("文件关闭失败: %s", strerror(errno));
    }
    
    return ret;
}

/**
 * read钩子函数
 */
ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real_read)(int, void *, size_t) = NULL;
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");
    
    DEBUG_LOG("调用read: fd=%d, 大小=%zu", fd, count);
    
    ssize_t ret = real_read(fd, buf, count);
    if (ret <= 0) {
        DEBUG_LOG("读取失败或结束: ret=%zd", ret);
        return ret;
    }
    
    // 获取上下文并检查是否为需要处理的文件
    fd_context_t *ctx = get_fd_context(fd);
    if (ctx && ctx->is_target) {
        update_fd_context(ctx);
        
        DEBUG_LOG("解密目标文件数据: fd=%d, 大小=%zd", fd, ret);
        
        // 执行解密操作
        unsigned char *data = (unsigned char *)buf;
        for (ssize_t i = 0; i < ret; ++i) {
            data[i] ^= 0xFF;
        }
        
        DEBUG_LOG("解密完成: 前3字节: %02x %02x %02x", data[0], data[1], data[2]);
    }
    
    return ret;
}

/**
 * mmap钩子函数
 */
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    static void *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
    if (!real_mmap) real_mmap = dlsym(RTLD_NEXT, "mmap");
    
    DEBUG_LOG("调用mmap: 地址=%p, 长度=%zu, 权限=0x%x, 标志=0x%x, fd=%d, 偏移=%ld", 
             addr, length, prot, flags, fd, (long)offset);
    
    void *ptr = real_mmap(addr, length, prot, flags, fd, offset);
    if (ptr == MAP_FAILED) {
        DEBUG_LOG("mmap失败: %s", strerror(errno));
        return ptr;
    }
    
    // 检查是否为需要处理的文件
    bool is_target = false;
    fd_context_t *ctx = get_fd_context(fd);
    if (ctx) {
        update_fd_context(ctx);
        is_target = ctx->is_target;
        
        if (is_target) {
            DEBUG_LOG("目标文件映射, 执行内存解密");
            safe_decrypt_mmap_region(ptr, length);
        }
    }
    
    // 添加内存映射跟踪
    add_mmap_region(ptr, length, prot, flags, fd, offset, is_target);
    
    return ptr;
}

/**
 * munmap钩子函数
 */
int munmap(void *addr, size_t length) {
    static int (*real_munmap)(void *, size_t) = NULL;
    if (!real_munmap) real_munmap = dlsym(RTLD_NEXT, "munmap");
    
    DEBUG_LOG("调用munmap: 地址=%p, 长度=%zu", addr, length);
    
    // 查找并处理关联区域
    pthread_mutex_lock(&mmap_mutex);
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == addr) {
            // 如果文件被修改且未加密，执行加密
            if (!mmap_regions[i].in_mem_encrypted && 
                mmap_regions[i].modified && 
                !mmap_regions[i].disk_encrypted) {
                DEBUG_LOG("区域被修改, 执行内存加密");
                safe_encrypt_mmap_region(addr, length);
            }
            break;
        }
    }
    pthread_mutex_unlock(&mmap_mutex);
    
    int ret = real_munmap(addr, length);
    if (ret == 0) {
        DEBUG_LOG("munmap成功");
        remove_mmap_region(addr);
    } else {
        DEBUG_LOG("munmap失败: %s", strerror(errno));
    }
    
    return ret;
}

// /**
//  * write钩子函数
//  */
// ssize_t write(int fd, const void *buf, size_t count) {
//     static ssize_t (*real_write)(int, const void *, size_t) = NULL;
//     if (!real_write) real_write = dlsym(RTLD_NEXT, "write");
    
//     DEBUG_LOG("调用write: fd=%d, 大小=%zu", fd, count);
    
//     fd_context_t *ctx = get_fd_context(fd);
//     if (!ctx || !ctx->is_target) {
//         return real_write(fd, buf, count);
//     }
    
//     update_fd_context(ctx);
//     DEBUG_LOG("写入目标文件, 执行加密");
    
//     // 分配临时缓冲区用于加密
//     void *encrypted_buf = malloc(count);
//     if (!encrypted_buf) {
//         DEBUG_LOG("内存分配失败");
//         errno = ENOMEM;
//         return -1;
//     }
    
//     // 加密数据
//     memcpy(encrypted_buf, buf, count);
//     unsigned char *data = (unsigned char *)encrypted_buf;
//     for (size_t i = 0; i < count; i++) {
//         data[i] ^= 0xFF;
//     }
    
//     // 写入加密后的数据
//     ssize_t ret = real_write(fd, encrypted_buf, count);
//     free(encrypted_buf);
    
//     if (ret > 0) {
//         DEBUG_LOG("写入成功: %zd字节", ret);
        
//         // 更新关联内存映射区域的磁盘状态
//         pthread_mutex_lock(&mmap_mutex);
//         for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
//             if (mmap_regions[i].fd == fd) {
//                 mmap_regions[i].disk_encrypted = true;
//                 DEBUG_LOG("标记区域为磁盘已加密: fd=%d, addr=%p", 
//                          fd, mmap_regions[i].addr);
//             }
//         }
//         pthread_mutex_unlock(&mmap_mutex);
//     } else {
//         DEBUG_LOG("写入失败: %s", strerror(errno));
//     }
    
//     return ret;
// }

// ==================== 初始化和清理 ====================

/**
 * 库加载时执行的构造函数
 */
__attribute__((constructor)) static void lib_init() {
    DEBUG_LOG("DWG透明加密钩子库已加载");
    
    // 初始化全局数据结构
    memset(fd_context_table, 0, sizeof(fd_context_table));
    memset(mmap_regions, 0, sizeof(mmap_regions));
    memset(hot_path_cache, 0, sizeof(hot_path_cache));
    
    DEBUG_LOG("全局数据结构初始化完成");
}

/**
 * 库卸载时执行的析构函数
 */
__attribute__((destructor)) static void lib_cleanup() {
    DEBUG_LOG("DWG透明加密钩子库卸载中...");
    
    // 清理所有FD上下文
    pthread_rwlock_wrlock(&fd_table_lock);
    for (int i = 0; i < MAX_TRACKED_FD; i++) {
        fd_context_t *ctx = fd_context_table[i];
        while (ctx) {
            fd_context_t *next = ctx->next;
            free(ctx->path);
            free(ctx);
            ctx = next;
        }
        fd_context_table[i] = NULL;
    }
    pthread_rwlock_unlock(&fd_table_lock);
    
    DEBUG_LOG("FD上下文清理完成");
    DEBUG_LOG("库卸载完成");
}