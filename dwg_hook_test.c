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
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <strings.h> // 用于strcasecmp
#include <sys/uio.h> // 用于readv/writev
#include <sys/sendfile.h> // 用于sendfile

// ==================== 配置选项 ====================
#define MAX_TRACKED_FD 1024        // 最大跟踪文件描述符数量
#define MAX_MMAP_REGIONS 256       // 最大跟踪内存映射区域数量
#define HOT_PATH_CACHE_SIZE 32     // 热点路径缓存大小
#define DEBUG_LOG_ENABLED 1         // 是否启用调试日志
#define DECRYPT_THRESHOLD 10        // 解密访问阈值
#define ENCRYPT_CHUNK (64*1024)    // 文件加密块大小(64KB)

// // ==================== 调试日志系统 ====================
// #define DEBUG_LOG(fmt, ...) \
//     do { \
//         if (DEBUG_LOG_ENABLED) { \
//             FILE *logfp = fopen("/tmp/dwg_hook.log", "a"); \
//             if (logfp) { \
//                 fprintf(logfp, "[DWG透明加解密] %s:%d " fmt "\n", \
//                         __func__, __LINE__, ##__VA_ARGS__); \
//                 fclose(logfp); \
//             } \
//         } \
//     } while (0)

// ==================== 调试日志系统(增强) ====================
#define DEBUG_LOG(fmt, ...) \
    do { \
        if (DEBUG_LOG_ENABLED) { \
            FILE *logfp = fopen("/tmp/dwg_hook.log", "a"); \
            if (logfp) { \
                struct timespec ts; \
                clock_gettime(CLOCK_REALTIME, &ts); \
                struct tm tm_time; \
                localtime_r(&ts.tv_sec, &tm_time); \
                fprintf(logfp, "[DWG透明加密][%02d:%02d:%02d.%03ld] %s:%d " fmt "\n", \
                        tm_time.tm_hour, tm_time.tm_min, tm_time.tm_sec, \
                        ts.tv_nsec / 1000000, \
                        __func__, __LINE__, ##__VA_ARGS__); \
                fclose(logfp); \
            } \
        } \
    } while (0)

// ==================== 数据结构定义 ====================

// 前置声明
typedef struct fd_context fd_context_t;
typedef struct mmap_region mmap_region_t;

// FD上下文结构：跟踪文件描述符相关信息
struct fd_context {
    int fd;                     // 文件描述符
    char *path;                 // 文件完整路径
    ino_t inode;                // 文件inode号
    dev_t device;               // 文件所在设备号
    bool is_target;             // 是否为目标DWG文件
    time_t last_verified;       // 最后验证时间戳
    int access_count;           // 访问计数器
    mmap_region_t *mmap_regions; // 关联的内存映射区域链表
    fd_context_t *next;         // 哈希冲突链表指针
};

// 增强的内存映射区域跟踪结构
struct mmap_region {
    void *addr;                 // 映射起始地址
    size_t length;              // 映射长度
    int prot;                   // 内存保护权限
    int flags;                  // 映射标志
    int fd;                     // 关联的文件描述符
    off_t offset;               // 文件偏移量
    bool modified;              // 是否被修改过
    bool in_mem_encrypted;      // 内存中是否加密
    bool disk_encrypted;        // 磁盘上是否加密
    mmap_region_t *next;        // 关联到同一fd的下一个区域
};

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

// ==================== 辅助函数声明 ====================
int is_target_dwg_file(const char *path);
static int safe_decrypt_mmap_region(void *addr, size_t length);
static int safe_encrypt_mmap_region(void *addr, size_t length);
static void xor_encrypt_decrypt(unsigned char *data, size_t length);
static int get_memory_protection(void *addr); // 新增：获取内存保护权限
static mmap_region_t *find_mmap_region(void *addr); // 新增：查找映射区域

// ==================== FD上下文管理 ====================

/**
 * 执行异或加解密操作（0xFF）
 * @param data 数据缓冲区
 * @param length 数据长度
 */
static void xor_encrypt_decrypt(unsigned char *data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        data[i] ^= 0xFF;  // 异或加密或解密
    }
}

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

    // ctx->path = realpath(path, NULL); // 获取绝对路径
    // if (!ctx->path) {
    //     ctx->path = strdup(path); // 回退到原始路径
    //     DEBUG_LOG("realpath失败, 使用原始路径: %s", path);
    // }

    // +++ 增强：详细记录路径处理过程 +++
    char *resolved_path = realpath(path, NULL);
    if (resolved_path) {
        ctx->path = resolved_path;
        DEBUG_LOG("路径解析成功: 原始路径=%s -> 绝对路径=%s", path, ctx->path);
    } else {
        ctx->path = strdup(path);
        DEBUG_LOG("路径解析失败, 使用原始路径: %s (错误: %s)", path, strerror(errno));
    }

    ctx->inode = st.st_ino;
    ctx->device = st.st_dev;
    ctx->is_target = is_target_dwg_file(ctx->path);
    ctx->last_verified = time(NULL);
    ctx->access_count = 0;
    ctx->mmap_regions = NULL;
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
    
    // +++ 增强：明确记录目标文件状态 +++
    if (ctx->is_target) {
        DEBUG_LOG("目标DWG文件已跟踪: fd=%d, 路径=%s", fd, ctx->path);
    } else {
        DEBUG_LOG("文件已跟踪: fd=%d, 路径=%s", fd, ctx->path);
    }

    // DEBUG_LOG("FD上下文初始化: fd=%d, 路径=%s, inode=%lu, 目标文件=%d", 
    //          fd, ctx->path, ctx->inode, ctx->is_target);
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
        if (ctx->mmap_regions == NULL) {
            ctx->mmap_regions = &mmap_regions[slot];
        } else {
            mmap_region_t *current = ctx->mmap_regions;
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
                mmap_region_t **prev = &ctx->mmap_regions;
                mmap_region_t *current = ctx->mmap_regions;
                
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

// ==================== 新增辅助函数 ====================

/**
 * 查找内存映射区域
 * @param addr 内存地址
 * @return 映射区域指针或NULL
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
 * 获取内存保护权限
 * @param addr 内存地址
 * @return 保护权限标志
 */
static int get_memory_protection(void *addr) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        DEBUG_LOG("[内存权限] 无法打开/proc/self/maps");
        return PROT_NONE;
    }
    
    int protection = PROT_NONE;
    char line[256];
    unsigned long start, end;
    uintptr_t addr_val = (uintptr_t)addr;  // 转换为整数类型便于比较
    
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
    DEBUG_LOG("[内存权限] 地址 %p 权限: %c%c%c (0x%x)", 
             addr,
             (protection & PROT_READ) ? 'r' : '-',
             (protection & PROT_WRITE) ? 'w' : '-',
             (protection & PROT_EXEC) ? 'x' : '-',
             protection);
    
    return protection;
}

// ==================== 加解密核心函数 ====================

// /**
//  * 判断是否为需要处理的目标DWG文件
//  * @param path 文件路径
//  * @return 1是目标文件，0不是
//  */
// int is_target_dwg_file(const char *path) {
//     if (!path) {
//         DEBUG_LOG("路径为空");
//         return 0;
//     }

//     // +++ 增强：记录所有文件访问尝试 +++
//     DEBUG_LOG("文件路径检查: %s", path);

//     size_t len = strlen(path);
//     if (len < 4) {
//         DEBUG_LOG("文件路径过短: %s", path);
//         return 0;
//     }
    
//     // 检查文件扩展名
//     const char *ext = path + len - 4;
//     if (strcasecmp(ext, ".dwg") != 0) {
//         DEBUG_LOG("文件不是.dwg格式: %s", path);
//         return 0;
//     }

//     // 检查路径中是否包含特定标识
//     if (strstr(path, "changed_") == NULL) {
//         DEBUG_LOG("文件路径不包含'changed_': %s", path);
//         return 0;
//     }

//     // 在识别目标文件时输出路径
//     DEBUG_LOG("目标DWG文件已识别: %s", path);
//     return 1;
// }

/**
 * 判断是否为需要处理的目标DWG文件（增强日志）
 */
int is_target_dwg_file(const char *path) {
    if (!path) {
        DEBUG_LOG("路径为空");
        return 0;
    }

    // +++ 增强：详细记录文件检查过程 +++
    DEBUG_LOG("文件路径检查: %s", path);
    
    size_t len = strlen(path);
    if (len < 4) {
        DEBUG_LOG("文件路径过短: %s", path);
        return 0;
    }
    
    // 检查文件扩展名
    const char *ext = path + len - 4;
    int is_dwg = (strcasecmp(ext, ".dwg") == 0);
    
    // 检查路径中是否包含特定标识
    int has_changed = (strstr(path, "changed_") != NULL);
    
    DEBUG_LOG("文件属性: DWG格式=%s, 包含changed_=%s", 
             is_dwg ? "是" : "否", has_changed ? "是" : "否");
    
    if (!is_dwg) {
        DEBUG_LOG("文件不是.dwg格式: %s", path);
        return 0;
    }

    if (!has_changed) {
        DEBUG_LOG("文件路径不包含'changed_': %s", path);
        return 0;
    }

    DEBUG_LOG("目标DWG文件已识别: %s", path);
    return 1;
}

/**
 * 安全解密内存映射区域（增强版，支持只读映射）
 * @param addr 起始地址
 * @param length 长度
 * @return 0成功，-1失败
 */
static int safe_decrypt_mmap_region(void *addr, size_t length) {
    if (!addr || length == 0) {
        DEBUG_LOG("无效参数");
        return -1;
    }

    // 获取当前内存保护属性
    int orig_prot = get_memory_protection(addr);
    
    // 只读内存特殊处理 - 使用新映射替换原映射
    if ((orig_prot & PROT_WRITE) == 0) {
        DEBUG_LOG("[内存解密] 只读内存区域，创建新映射进行解密");
        
        // 1. 创建新的可读写匿名映射
        void *new_map = mmap(NULL, length, PROT_READ | PROT_WRITE, 
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (new_map == MAP_FAILED) {
            DEBUG_LOG("[内存解密] 匿名映射创建失败: %s", strerror(errno));
            return -1;
        }
        
        // 2. 复制数据到新映射
        memcpy(new_map, addr, length);
        
        // 3. 解密新映射区域
        unsigned char *data = (unsigned char *)new_map;
        xor_encrypt_decrypt(data, length);
        
        // 4. 解除原只读映射
        if (munmap(addr, length)) {
            DEBUG_LOG("[内存解密] 解除原映射失败: %s", strerror(errno));
            munmap(new_map, length);
            return -1;
        }
        
        // 5. 重新映射到原地址
        void *remap = mmap(addr, length, PROT_READ | PROT_WRITE, 
                          MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
        if (remap != addr) {
            DEBUG_LOG("[内存解密] 重新映射失败: 期望=%p, 实际=%p", addr, remap);
            munmap(new_map, length);
            return -1;
        }
        
        // 6. 复制解密数据回原地址
        memcpy(addr, new_map, length);
        munmap(new_map, length);
        
        // 7. 恢复原始保护属性
        if (mprotect(addr, length, orig_prot)) {
            DEBUG_LOG("[内存解密] 恢复权限失败: %s", strerror(errno));
        }
        
        DEBUG_LOG("[内存解密] 通过映射替换完成解密");
        return 0;
    }

    // 常规可写内存处理
    if (mprotect(addr, length, PROT_READ | PROT_WRITE) != 0) {
        DEBUG_LOG("[内存解密] mprotect失败: %s (原始权限:0x%x)", 
                 strerror(errno), orig_prot);
        return -1;
    }

    DEBUG_LOG("[内存解密] 权限修改成功: %p+%zu 可读写 (原始权限:0x%x)", 
             addr, length, orig_prot);

    // 执行异或解密
    unsigned char *data = (unsigned char *)addr;
    xor_encrypt_decrypt(data, length);

    DEBUG_LOG("[内存解密] 解密完成: %p+%zu (前3字节: %02x %02x %02x)",
              addr, length, data[0], data[1], data[2]);

    // 恢复原始保护属性
    if (mprotect(addr, length, orig_prot) != 0) {
        DEBUG_LOG("[内存解密] 恢复权限失败: %s", strerror(errno));
    } else {
        DEBUG_LOG("[内存解密] 权限恢复: %p+%zu -> 0x%x", addr, length, orig_prot);
    }

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
        DEBUG_LOG("[内存加密] 无效地址或长度");
        return -1;
    }

    // 获取当前内存保护属性
    int orig_prot = get_memory_protection(addr);
    
    // 临时修改内存权限为可写
    if (mprotect(addr, length, PROT_READ | PROT_WRITE) != 0) {
        DEBUG_LOG("[内存加密] mprotect失败: %s", strerror(errno));
        return -1;
    }

    // 执行异或加密
    unsigned char *data = (unsigned char *)addr;
    xor_encrypt_decrypt(data, length);

    DEBUG_LOG("[内存加密] 加密完成: %p+%zu (前3字节: %02x %02x %02x)",
              addr, length, data[0], data[1], data[2]);

    // 恢复原始权限
    if (mprotect(addr, length, orig_prot) != 0) {
        DEBUG_LOG("[内存加密] 恢复权限失败: %s", strerror(errno));
    }

    // 更新 region 状态
    pthread_mutex_lock(&mmap_mutex);
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == addr) {
            mmap_regions[i].in_mem_encrypted = true;
            mmap_regions[i].disk_encrypted = true;
            mmap_regions[i].modified = false;
            break;
        }
    }
    pthread_mutex_unlock(&mmap_mutex);
    
    DEBUG_LOG("[内存加密] 更新状态: 地址=%p, 长度=%zu, in_mem_encrypted=true", addr, length);

    return 0;
}

/**
 * 文件加密函数（用于重命名后加密）
 * @param path 文件路径
 * @return 0成功，-1失败
 */
static int encrypt_file_on_disk(const char *path) {
    if (!path) return -1;
    int fd = open(path, O_RDWR);
    if (fd < 0) {
        DEBUG_LOG("encrypt_file_on_disk: 打开失败 %s: %s", path, strerror(errno));
        return -1;
    }

    // 获取文件长度
    off_t size = lseek(fd, 0, SEEK_END);
    if (size == (off_t)-1) {
        DEBUG_LOG("encrypt_file_on_disk: lseek失败 %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }

    // 分块读取->异或->写回（使用 pwrite）
    unsigned char *buf = malloc(ENCRYPT_CHUNK);
    if (!buf) {
        DEBUG_LOG("encrypt_file_on_disk: 内存分配失败");
        close(fd);
        return -1;
    }

    off_t off = 0;
    while (off < size) {
        size_t toread = (size - off) > ENCRYPT_CHUNK ? ENCRYPT_CHUNK : (size - off);
        ssize_t n = pread(fd, buf, toread, off);
        if (n <= 0) {
            DEBUG_LOG("encrypt_file_on_disk: pread 失败 off=%ld %s", (long)off, strerror(errno));
            break;
        }
        xor_encrypt_decrypt(buf, n); // 加密数据
        ssize_t w = pwrite(fd, buf, n, off);
        if (w != n) {
            DEBUG_LOG("encrypt_file_on_disk: pwrite 失败 off=%ld w=%zd err=%s", (long)off, w, strerror(errno));
            break;
        }
        off += n;
    }

    free(buf);
    // 确保写回磁盘
    fsync(fd);
    close(fd);

    DEBUG_LOG("encrypt_file_on_disk: 完成对文件加密: %s (大小=%ld)", path, (long)size);
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
    
    // +++ 关键增强：详细记录所有打开尝试 +++
    DEBUG_LOG("==========================================================");
    DEBUG_LOG("文件打开尝试: %s (标志:0x%x, 模式:0%o)", 
             pathname ? pathname : "(null)", flags, mode);
    
    int fd = (flags & O_CREAT) ? 
        real_open(pathname, flags, mode) : 
        real_open(pathname, flags);
    
    // if (fd >= 0) {
    //     init_fd_context(fd, pathname);
    //     add_hot_path(pathname, 0, 0);
    //     DEBUG_LOG("文件打开成功: fd=%d, 路径=%s", fd, pathname);

    //     // +++ 新增：检查并输出加密文件打开日志 +++
    //     fd_context_t *ctx = get_fd_context(fd);
    //     if (ctx && ctx->is_target) {
    //         DEBUG_LOG("已成功打开加密DWG文件: %s ", ctx->path);
    //     }
    // } else {
    //     DEBUG_LOG("文件打开失败: %s, 错误: %s", 
    //              pathname ? pathname : "(null)", strerror(errno));
        
    //     // +++ 新增：即使打开失败，也检查是否目标文件 +++
    //     if (pathname && is_target_dwg_file(pathname)) {
    //         DEBUG_LOG("目标DWG文件打开失败: %s", pathname);
    //     }
    // }

    if (fd >= 0) {
        DEBUG_LOG("文件打开成功: fd=%d", fd);
        
        if (pathname) {
            init_fd_context(fd, pathname);
            add_hot_path(pathname, 0, 0);
            
            // +++ 立即检查是否目标文件 +++
            fd_context_t *ctx = get_fd_context(fd);
            if (ctx && ctx->is_target) {
                DEBUG_LOG("已打开加密DWG文件: %s", ctx->path);
            }
        } else {
            DEBUG_LOG("警告: 成功打开文件但路径为空!");
        }
    } else {
        DEBUG_LOG("文件打开失败: 错误: %s", strerror(errno));
        
        // +++ 即使打开失败也尝试识别目标文件 +++
        if (pathname && is_target_dwg_file(pathname)) {
            DEBUG_LOG("目标DWG文件打开失败: %s", pathname);
        }
    }
    
    DEBUG_LOG("==========================================================");
    
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
    
    // +++ 关键增强：详细记录所有打开尝试 +++
    DEBUG_LOG("==========================================================");
    DEBUG_LOG("文件打开尝试: 目录fd=%d, 路径=%s, 标志=0x%x, 模式=0%o", 
             dirfd, pathname ? pathname : "(null)", flags, mode);
    
    int fd = (flags & O_CREAT) ? 
        real_openat(dirfd, pathname, flags, mode) : 
        real_openat(dirfd, pathname, flags);
    
    // if (fd >= 0) {
    //     init_fd_context(fd, pathname);
    //     add_hot_path(pathname, 0, 0);
    //     DEBUG_LOG("文件打开成功: fd=%d, 路径=%s", fd, pathname);

    //     // 检查是否为加密DWG文件
    //     fd_context_t *ctx = get_fd_context(fd);
    //     if (ctx && ctx->is_target) {
    //         DEBUG_LOG("已成功打开加密DWG文件: %s ", ctx->path);
    //     }
    // } else {
    //     DEBUG_LOG("文件打开失败: %s, 错误: %s", 
    //              pathname ? pathname : "(null)", strerror(errno));
        
    //     // +++ 新增：即使打开失败，也检查是否目标文件 +++
    //     if (pathname && is_target_dwg_file(pathname)) {
    //         DEBUG_LOG("目标DWG文件打开失败: %s", pathname);
    //     }
    // }
    

    if (fd >= 0) {
        DEBUG_LOG("文件打开成功: fd=%d", fd);
        
        if (pathname) {
            init_fd_context(fd, pathname);
            add_hot_path(pathname, 0, 0);
            
            // +++ 立即检查是否目标文件 +++
            fd_context_t *ctx = get_fd_context(fd);
            if (ctx && ctx->is_target) {
                DEBUG_LOG("已打开加密DWG文件: %s", ctx->path);
            }
        } else {
            DEBUG_LOG("警告: 成功打开文件但路径为空!");
        }
    } else {
        DEBUG_LOG("文件打开失败: 错误: %s", strerror(errno));
        
        // +++ 即使打开失败也尝试识别目标文件 +++
        if (pathname && is_target_dwg_file(pathname)) {
            DEBUG_LOG("目标DWG文件打开失败: %s", pathname);
        }
    }
    
    DEBUG_LOG("==========================================================");

    return fd;
}


/**
 * read钩子函数
 */
ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real_read)(int, void *, size_t) = NULL;
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");
    
    // 获取上下文
    fd_context_t *ctx = get_fd_context(fd);

    // +++ 增强：记录所有读取操作 +++
    const char *path = ctx ? ctx->path : "(未知)";
    DEBUG_LOG("读取操作: fd=%d, 路径=%s, 大小=%zu", fd, path, count);

    ssize_t ret = real_read(fd, buf, count);
    if (ret <= 0) {
        DEBUG_LOG("读取失败或结束: ret=%zd", ret);
        return ret;
    }
    
    // 检查是否为需要处理的文件
    if (ctx && ctx->is_target) {
        update_fd_context(ctx);
        
        DEBUG_LOG("解密目标文件数据: %s, 大小=%zd", ctx->path, ret);
        
        // 执行解密操作
        unsigned char *data = (unsigned char *)buf;
        xor_encrypt_decrypt(data, ret);  // 解密数据
        
        DEBUG_LOG("解密完成: 前3字节: %02x %02x %02x", data[0], data[1], data[2]);
    } else if (ctx) {
        DEBUG_LOG("非目标文件读取: %s", ctx->path);
    } else {
        DEBUG_LOG("未跟踪文件读取: fd=%d", fd);
    }
    
    return ret;
}

/**
 * mmap钩子函数（增强版）
 */
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    static void *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
    if (!real_mmap) real_mmap = dlsym(RTLD_NEXT, "mmap");
    
    // 获取上下文
    fd_context_t *ctx = get_fd_context(fd);

    // +++ 增强：在映射前记录文件信息 +++
    const char *path = ctx ? ctx->path : "(未知)";
    DEBUG_LOG("映射操作: fd=%d, 路径=%s, 地址=%p, 长度=%zu", fd, path, addr, length);
    
    void *ptr = real_mmap(addr, length, prot, flags, fd, offset);
    if (ptr == MAP_FAILED) {
        DEBUG_LOG("mmap失败: %s", strerror(errno));

        // +++ 增强：记录目标文件映射失败 +++
        if (ctx && ctx->is_target) {
            DEBUG_LOG("加密DWG文件映射失败: %s", ctx->path);
        }

        return ptr;
    }
    
    // 检查是否为需要处理的文件
    bool is_target = false;
    // fd_context_t *ctx = get_fd_context(fd);
    if (ctx) {
        update_fd_context(ctx);
        is_target = ctx->is_target;
        
        if (is_target) {
            DEBUG_LOG("目标文件映射: %s, 执行内存解密", ctx->path);
            if (safe_decrypt_mmap_region(ptr, length) == 0) {
                // 更新映射区域状态
                pthread_mutex_lock(&mmap_mutex);
                for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
                    if (mmap_regions[i].addr == ptr) {
                        mmap_regions[i].in_mem_encrypted = false;
                        mmap_regions[i].disk_encrypted = true;
                        break;
                    }
                }
                pthread_mutex_unlock(&mmap_mutex);
            
                DEBUG_LOG("内存解密成功: %s", ctx->path);
            } else {
                DEBUG_LOG("内存解密失败: %s", ctx->path);
            }
        }
    }
    
    // 添加内存映射跟踪
    add_mmap_region(ptr, length, prot, flags, fd, offset, is_target);
    
    return ptr;
}

/**
 * munmap钩子函数（增强版）
 */
int munmap(void *addr, size_t length) {
    static int (*real_munmap)(void *, size_t) = NULL;
    if (!real_munmap) real_munmap = dlsym(RTLD_NEXT, "munmap");
    
    DEBUG_LOG("调用munmap: 地址=%p, 长度=%zu", addr, length);
    
    // 查找并处理关联区域
    mmap_region_t *region = find_mmap_region(addr);
    
    // 需要加密的情况：目标文件+已修改+磁盘未加密
    if (region && region->in_mem_encrypted == false && 
        region->modified && !region->disk_encrypted) {
        DEBUG_LOG("区域被修改, 执行内存加密");
        if (safe_encrypt_mmap_region(addr, length) == 0) {
            // 同步到磁盘
            if (region->fd >= 0) {
                msync(addr, length, MS_SYNC);
            }
        }
    }
    
    int ret = real_munmap(addr, length);
    if (ret == 0) {
        DEBUG_LOG("munmap成功");
        remove_mmap_region(addr);
    } else {
        DEBUG_LOG("munmap失败: %s", strerror(errno));
    }
    
    return ret;
}

/**
 * write钩子函数（增强版）
 */
ssize_t write(int fd, const void *buf, size_t count) {
    static ssize_t (*real_write)(int, const void *, size_t) = NULL;
    if (!real_write) real_write = dlsym(RTLD_NEXT, "write");
    
    fd_context_t *ctx = get_fd_context(fd);

    // +++ 增强：在写入前记录文件信息 +++
    const char *path = ctx ? ctx->path : "(未知)";
    DEBUG_LOG("写入操作: fd=%d, 路径=%s, 大小=%zu", fd, path, count);

    if (!ctx || !ctx->is_target || count == 0 || !buf) {
        return real_write(fd, buf, count);
    }
    
    update_fd_context(ctx);
    DEBUG_LOG("写入目标文件, 执行加密");
    
    // 分配临时缓冲区用于加密
    void *encrypted_buf = malloc(count);
    if (!encrypted_buf) {
        DEBUG_LOG("内存分配失败");
        errno = ENOMEM;
        return -1;
    }
    
    // 加密数据
    memcpy(encrypted_buf, buf, count);
    unsigned char *data = (unsigned char *)encrypted_buf;
    xor_encrypt_decrypt(data, count);
    
    // 写入加密后的数据
    ssize_t ret = real_write(fd, encrypted_buf, count);
    free(encrypted_buf);
    
    if (ret > 0) {
        DEBUG_LOG("写入成功: %zd字节", ret);
        
        // 更新关联内存映射区域的磁盘状态
        pthread_mutex_lock(&mmap_mutex);
        for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
            if (mmap_regions[i].fd == fd) {
                mmap_regions[i].disk_encrypted = true;
                DEBUG_LOG("标记区域为磁盘已加密: fd=%d, addr=%p", 
                         fd, mmap_regions[i].addr);
            }
        }
        pthread_mutex_unlock(&mmap_mutex);
    } else {
        DEBUG_LOG("写入失败: %s", strerror(errno));
    }
    
    return ret;
}

/**
 * msync钩子函数（新增）
 */
int msync(void *addr, size_t length, int flags) {
    static int (*real_msync)(void *, size_t, int) = NULL;
    if (!real_msync) real_msync = dlsym(RTLD_NEXT, "msync");
    
    DEBUG_LOG("调用msync: 地址=%p, 长度=%zu, 标志=0x%x", addr, length, flags);
    
    mmap_region_t *region = find_mmap_region(addr);
    if (region && region->in_mem_encrypted == false && 
        region->modified && !region->disk_encrypted) 
    {
        DEBUG_LOG("区域需要加密后同步");
        // 加密内存区域
        if (safe_encrypt_mmap_region(addr, length) == 0) {
            // 执行真实msync
            int ret = real_msync(addr, length, flags);
            // 解密回内存
            safe_decrypt_mmap_region(addr, length);
            // 更新状态
            region->modified = false;
            return ret;
        }
    }
    return real_msync(addr, length, flags);
}

/**
 * mprotect钩子函数（新增）
 */
int mprotect(void *addr, size_t len, int prot) {
    static int (*real_mprotect)(void *, size_t, int) = NULL;
    if (!real_mprotect) real_mprotect = dlsym(RTLD_NEXT, "mprotect");
    
    DEBUG_LOG("调用mprotect: 地址=%p, 长度=%zu, 权限=0x%x", addr, len, prot);
    
    // 如果设置为可写，标记映射区域为已修改
    if (prot & PROT_WRITE) {
        mmap_region_t *region = find_mmap_region(addr);
        if (region) {
            region->modified = true;
            region->disk_encrypted = false;
            DEBUG_LOG("标记区域为可写: 地址=%p, 长度=%zu", addr, len);
        }
    }
    
    return real_mprotect(addr, len, prot);
}

/**
 * rename钩子函数（新增）
 */
int rename(const char *oldpath, const char *newpath) {
    static int (*real_rename)(const char *, const char *) = NULL;
    if (!real_rename) real_rename = dlsym(RTLD_NEXT, "rename");

    DEBUG_LOG("调用rename: %s -> %s", oldpath?oldpath:"(null)", newpath?newpath:"(null)");
    int ret = real_rename(oldpath, newpath);

    if (ret == 0 && newpath && is_target_dwg_file(newpath)) {
        // 新路径是目标 DWG，确保磁盘文件被加密
        if (encrypt_file_on_disk(newpath) != 0) {
            DEBUG_LOG("rename: 对 newpath 加密失败 %s", newpath);
        }
    }

    return ret;
}

/**
 * renameat钩子函数（新增）
 */
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    static int (*real_renameat)(int, const char *, int, const char *) = NULL;
    if (!real_renameat) real_renameat = dlsym(RTLD_NEXT, "renameat");

    DEBUG_LOG("调用renameat: %d:%s -> %d:%s", 
             olddirfd, oldpath?oldpath:"(null)", 
             newdirfd, newpath?newpath:"(null)");
    int ret = real_renameat(olddirfd, oldpath, newdirfd, newpath);

    if (ret == 0 && newpath && is_target_dwg_file(newpath)) {
        if (encrypt_file_on_disk(newpath) != 0) {
            DEBUG_LOG("renameat: 对 newpath 加密失败 %s", newpath);
        }
    }

    return ret;
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

// ==================== 初始化和清理 ====================

/**
 * 库加载时执行的构造函数
 */
__attribute__((constructor)) static void lib_init() {
    DEBUG_LOG("DWG透明加解密钩子库已加载");
    
    // 初始化全局数据结构
    memset(fd_context_table, 0, sizeof(fd_context_table));
    memset(mmap_regions, 0, sizeof(mmap_regions));
    memset(hot_path_cache, 0, sizeof(hot_path_cache));
    
    DEBUG_LOG("全局数据结构初始化完成");

    // +++ 增强：记录关键配置 +++
    DEBUG_LOG("配置参数: MAX_TRACKED_FD=%d, MAX_MMAP_REGIONS=%d", 
             MAX_TRACKED_FD, MAX_MMAP_REGIONS);
    DEBUG_LOG("解密阈值: DECRYPT_THRESHOLD=%d, 加密块大小: ENCRYPT_CHUNK=%d", 
             DECRYPT_THRESHOLD, ENCRYPT_CHUNK);
    DEBUG_LOG("调试日志: %s", DEBUG_LOG_ENABLED ? "启用" : "禁用");

     // +++ 增强：检查环境变量 +++
     const char *debug_env = getenv("DWG_HOOK_DEBUG");
     if (debug_env) {
         DEBUG_LOG("环境变量 DWG_HOOK_DEBUG=%s", debug_env);
     }
     
     DEBUG_LOG("全局数据结构初始化完成");
}

/**
 * 库卸载时执行的析构函数
 */
__attribute__((destructor)) static void lib_cleanup() {
    DEBUG_LOG("DWG透明加密钩子库卸载中...");
    
    // 清理所有FD上下文
    int ctx_count = 0;
    pthread_rwlock_wrlock(&fd_table_lock);
    for (int i = 0; i < MAX_TRACKED_FD; i++) {
        fd_context_t *ctx = fd_context_table[i];
        while (ctx) {
            fd_context_t *next = ctx->next;

            // +++ 增强：记录清理的上下文 +++
            DEBUG_LOG("清理FD上下文: fd=%d, 路径=%s", ctx->fd, ctx->path);

            free(ctx->path);
            free(ctx);
            ctx = next;
            ctx_count++;
        }
        fd_context_table[i] = NULL;
    }
    pthread_rwlock_unlock(&fd_table_lock);
    
    DEBUG_LOG("FD上下文清理完成: 共清理 %d 个上下文", ctx_count);
    DEBUG_LOG("库卸载完成");
}