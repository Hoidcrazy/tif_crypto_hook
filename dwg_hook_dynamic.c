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

// 全局数组：存储文件描述符 (fd) 到文件路径字符串的映射
static char *fd_paths[MAX_TRACKED_FD] = {0};

// 互斥锁：保护 fd_paths 数组的读写操作
static pthread_mutex_t fd_mutex = PTHREAD_MUTEX_INITIALIZER;

// 调试标志：控制是否输出调试日志
static int debug_enabled = -1;

// inode缓存大小
#define INODE_CACHE_SIZE 1024

// inode缓存结构
typedef struct {
    ino_t inode;      // 文件inode号
} inode_cache_t;

static inode_cache_t inode_cache[INODE_CACHE_SIZE] = {{0}};
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
    bool in_memory_encrypted; // 内存中是否已是加密状态
    bool disk_encrypted;      // 磁盘上是否为加密内容（与内存是否同步）
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

// 查找并返回第一个空槽索引，否则-1
static int find_free_mmap_slot_locked() {
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == NULL) return i;
    }
    return -1;
}

// 查找映射区域（按地址精确匹配）
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

// 通过 fd 查找任意映射区域（用于 write/pwrite 标记）
static void mark_regions_disk_encrypted_for_fd(int fd) {
    pthread_mutex_lock(&mmap_mutex);
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == NULL) continue;
        if (mmap_regions[i].fd == fd) {
            mmap_regions[i].disk_encrypted = true;
            // 如果我们写的是加密数据到磁盘，而内存是解密的，保持 in_memory_encrypted=false
            DEBUG_LOG("标记 region fd=%d addr=%p+%zu 为 disk_encrypted=true", fd, mmap_regions[i].addr, mmap_regions[i].length);
        }
    }
    pthread_mutex_unlock(&mmap_mutex);
}

// 标记特定偏移范围的 region 为 disk_encrypted（用于 pwrite64）
static void mark_regions_disk_encrypted_for_fd_range(int fd, off_t offset, size_t count) {
    pthread_mutex_lock(&mmap_mutex);
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == NULL) continue;
        if (mmap_regions[i].fd != fd) continue;

        off_t reg_start_off = mmap_regions[i].offset;
        off_t reg_end_off = mmap_regions[i].offset + (off_t)mmap_regions[i].length;
        off_t write_start = offset;
        off_t write_end = offset + (off_t)count;

        // 判断是否有交集
        if (!(write_end <= reg_start_off || write_start >= reg_end_off)) {
            mmap_regions[i].disk_encrypted = true;
            DEBUG_LOG("标记 region(fd=%d) 偏移覆盖为 disk_encrypted=true (write %ld..%ld overlap %ld..%ld)",
                      fd, (long)write_start, (long)write_end, (long)reg_start_off, (long)reg_end_off);
        }
    }
    pthread_mutex_unlock(&mmap_mutex);
}

/**
 * 修改mmap区域跟踪
 * 若 should_decrypt 为 1，表示我们会对该区域尝试解密（内存解密后要设置 in_memory_encrypted=false）
 */
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
        // 假设文件磁盘上原始是加密的（我们只对目标文件做这个流程）
        if (should_decrypt) {
            // 在 mmap 后我们会尝试解密内存，如果解密成功会将 in_memory_encrypted=false
            mmap_regions[slot].in_memory_encrypted = true; // 先假设内存跟磁盘相同（加密）
            mmap_regions[slot].disk_encrypted = true;
        } else {
            mmap_regions[slot].in_memory_encrypted = true;
            mmap_regions[slot].disk_encrypted = true;
        }
        DEBUG_LOG("[内存映射] 跟踪区域新建: slot=%d addr=%p len=%zu fd=%d should_decrypt=%d",
                 slot, addr, length, fd, should_decrypt);
    } else {
        DEBUG_LOG("[内存映射] 无可用插槽来跟踪 addr=%p len=%zu", addr, length);
    }

    pthread_mutex_unlock(&mmap_mutex);
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

// 查找 region 的下标（方便内部更新状态）
static int find_mmap_region_index_by_addr(void *addr) {
    int idx = -1;
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == addr) {
            idx = i;
            break;
        }
    }
    return idx;
}

// 修改后的内存权限查询函数
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

// 解密内存映射区域（安全版），成功后标记对应 region 状态
// 修改后的安全内存解密函数
static int safe_decrypt_mmap_region(void *addr, size_t length) {
    if (!addr || length == 0) {
        DEBUG_LOG("[内存解密] 无效地址或长度");
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
        for (size_t i = 0; i < length; ++i) {
            data[i] ^= 0xFF;
        }
        
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
    for (size_t i = 0; i < length; ++i) {
        data[i] ^= 0xFF;
    }

    DEBUG_LOG("[内存解密] 解密完成: %p+%zu (前3字节: %02x %02x %02x ...)",
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
 * 安全内存加密，成功后标记 region 状态
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

    // 更新 region 状态
    pthread_mutex_lock(&mmap_mutex);
    int idx = find_mmap_region_index_by_addr(addr);
    if (idx >= 0) {
        mmap_regions[idx].in_memory_encrypted = true;
        mmap_regions[idx].disk_encrypted = true;
        mmap_regions[idx].modified = false; // 已加密并同步到磁盘
    }
    pthread_mutex_unlock(&mmap_mutex);
    DEBUG_LOG("[内存加密] 更新状态: 地址=%p, 长度=%zu, in_memory_encrypted=true", addr, length);

    return 0;
}

// ---------- 新增：在重命名后对目标文件进行磁盘加密 (避免临时文件写入后替换为明文) ----------

#define ENCRYPT_CHUNK (64*1024)

// 简单判断文件是否看起来是明文 DWG（只读前 4 字节）
static int file_looks_plain_dwg(int fd) {
    unsigned char hdr[8] = {0};
    ssize_t r = pread(fd, hdr, sizeof(hdr), 0);
    if (r <= 0) return 0;
    // 常见 DWG ASCII 开头 "AC10", "AC1012", "AC1021", "AC1032" 等，判断前4字节是否为 "AC1" ...
    if (hdr[0] == 'A' && hdr[1] == 'C' && hdr[2] == '1') return 1;
    return 0;
}

static int encrypt_file_on_disk(const char *path) {
    if (!path) return -1;
    int fd = open(path, O_RDWR);
    if (fd < 0) {
        DEBUG_LOG("encrypt_file_on_disk: 打开失败 %s: %s", path, strerror(errno));
        return -1;
    }

    // 如果文件看起来不是明文 DWG，就跳过（避免重复加密）
    if (!file_looks_plain_dwg(fd)) {
        close(fd);
        DEBUG_LOG("encrypt_file_on_disk: 文件看起来非明文或已加密，跳过: %s", path);
        return 0;
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
        for (ssize_t i = 0; i < n; ++i) buf[i] ^= 0xFF;
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
    
    // 仅使用路径匹配判断是否需要处理
    int is_target = path && is_target_dwg_file(path);
    
    DEBUG_LOG("pread64(fd=%d, 偏移=%ld, 大小=%zu, 返回值=%zd, 路径=%s)%s",
              fd, (long)offset, count, ret,
              path ? path : "(未知)",
              is_target ? " [已解密]" : "");

    if (is_target) {
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
    
    // 仅使用路径匹配判断是否需要处理
    int is_target = path && is_target_dwg_file(path);

    DEBUG_LOG("read(fd=%d, 大小=%zu, 返回值=%zd, 路径=%s)%s",
              fd, count, ret,
              path ? path : "(未知)",
              is_target ? " [已解密]" : "");

    if (is_target) {
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

// 修改mmap函数
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    static void *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
    if (!real_mmap)
        real_mmap = dlsym(RTLD_NEXT, "mmap");

    char path_buf[PATH_MAX] = {0};
    const char *path = NULL;
    
    if (fd >= 0) {
        path = get_fd_path(fd, path_buf, sizeof(path_buf));
    }
    
    // 仅使用路径匹配判断是否需要处理
    int is_target = path && is_target_dwg_file(path);

    DEBUG_LOG("mmap: 地址=%p, 长度=%zu, 权限=0x%x, 标志=0x%x, fd=%d, 偏移=%ld, 路径=%s",
              addr, length, prot, flags, fd, (long)offset, path ? path : "(无fd)");

    void *ptr = real_mmap(addr, length, prot, flags, fd, offset);
    if (ptr == MAP_FAILED) {
        DEBUG_LOG("mmap 失败: 错误=%d (%s)", errno, strerror(errno));
        return ptr;
    }

    if (is_target) {
        DEBUG_LOG("[内存映射] 目标文件映射: fd=%d, 路径=%s, 区域=%p+%zu", fd, path, ptr, length);

        // 先 track，然后尝试解密，这样 track_mmap_region 可以记录初始状态
        track_mmap_region(ptr, length, 1, prot, flags, fd, offset);
        
        // 尝试解密，即使失败也继续
        if (safe_decrypt_mmap_region(ptr, length) != 0) {
            DEBUG_LOG("[警告] 内存映射解密失败，数据可能未解密");
        }
    } else {
        DEBUG_LOG("mmap: 此映射无需解密 (fd=%d)", fd);
        track_mmap_region(ptr, length, 0, prot, flags, fd, offset);
    }

    // track_mmap_region(ptr, length, is_target, prot, flags, fd, offset);

    return ptr;
}

// 同样修改mmap64函数
void *mmap64(void *addr, size_t length, int prot, int flags, int fd, off64_t offset) {
    static void *(*real_mmap64)(void *, size_t, int, int, int, off64_t) = NULL;
    if (!real_mmap64)
        real_mmap64 = dlsym(RTLD_NEXT, "mmap64");

    char path_buf[PATH_MAX] = {0};
    const char *path = NULL;

    if (fd >= 0) {
        path = get_fd_path(fd, path_buf, sizeof(path_buf));
    }
    
    // 仅使用路径匹配判断是否需要处理
    int is_target = path && is_target_dwg_file(path);

    DEBUG_LOG("mmap64: 地址=%p, 长度=%zu, 权限=0x%x, 标志=0x%x, fd=%d, 偏移=%lld, 路径=%s",
              addr, length, prot, flags, fd, (long long)offset, path ? path : "(无fd)");

    void *ptr = real_mmap64(addr, length, prot, flags, fd, offset);
    if (ptr == MAP_FAILED) {
        DEBUG_LOG("mmap64 失败: 错误=%d (%s)", errno, strerror(errno));
        return ptr;
    }

    if (is_target) {
        DEBUG_LOG("[内存映射64] 目标文件映射: fd=%d, 路径=%s, 区域=%p+%zu", fd, path, ptr, length);
        
        track_mmap_region(ptr, length, 1, prot, flags, fd, (off_t)offset);

        if (safe_decrypt_mmap_region(ptr, length) != 0) {
            DEBUG_LOG("[警告] 内存映射解密失败 (mmap64)，数据可能未解密");
        }
    } else {
        DEBUG_LOG("mmap64: 此映射无需解密 (fd=%d)", fd);
        track_mmap_region(ptr, length, 0, prot, flags, fd, (off_t)offset);
    }

    // track_mmap_region(ptr, length, is_target, prot, flags, fd, offset);

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

    // 查找 region（谨慎处理，先拷贝 index 再解锁）
    pthread_mutex_lock(&mmap_mutex);
    int idx = -1;
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == addr) {
            idx = i;
            break;
        }
    }
    if (idx >= 0) {
        mmap_region_t region_copy = mmap_regions[idx]; // 复制以便解锁后操作
        pthread_mutex_unlock(&mmap_mutex);

        if (region_copy.should_decrypt && region_copy.modified && !region_copy.disk_encrypted) {
            DEBUG_LOG("munmap: 区域 %p+%zu 需要加密后再解除映射", addr, length);
            // 加密并同步：如果失败，尽量继续，以免内存泄漏
            if (safe_encrypt_mmap_region(addr, length) != 0) {
                DEBUG_LOG("[警告] munmap: 加密失败，文件可能未正确加密");
            } else {
                // 同步到磁盘
                if (region_copy.fd >= 0) {
                    msync(addr, length, MS_SYNC);
                }
            }
        } else {
            DEBUG_LOG("munmap: 无需加密或已加密 (%s, modified=%d, disk_encrypted=%d)",
                      region_copy.should_decrypt ? "target" : "not_target",
                      region_copy.modified, region_copy.disk_encrypted);
        }
    } else {
        pthread_mutex_unlock(&mmap_mutex);
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


// ==================== 写入加密功能(增强版) ====================

ssize_t write(int fd, const void *buf, size_t count) {
    static ssize_t (*real_write)(int, const void *, size_t) = NULL;
    if (!real_write)
        real_write = dlsym(RTLD_NEXT, "write");

    char path_buf[PATH_MAX] = {0};
    const char *path = get_fd_path(fd, path_buf, sizeof(path_buf));
    
    int is_target = path && is_target_dwg_file(path);
    
    DEBUG_LOG("write(fd=%d, 大小=%zu, 路径=%s, 目标文件=%d)",
              fd, count, path ? path : "(未知)", is_target);

    if (!is_target || count == 0 || !buf) {
        return real_write(fd, buf, count);
    }

    // 仍然使用临时缓冲区加密后写入磁盘（保证磁盘始终保存加密数据）
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

    DEBUG_LOG("write: 加密后写入 (fd=%d) 前3字节: %02x %02x %02x ...", fd, data[0], data[1], data[2]);

    ssize_t ret = real_write(fd, encrypted_buf, count);
    free(encrypted_buf);

    if (ret >= 0) {
        // 标记相关 mmap region 磁盘上已经是加密内容，避免后续 msync/munmap 重复加密
        mark_regions_disk_encrypted_for_fd(fd);
    }

    DEBUG_LOG("write: 返回 %zd %s", ret, ret < 0 ? strerror(errno) : "");
    return ret;
}

ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset) {
    static ssize_t (*real_pwrite64)(int, const void *, size_t, off_t) = NULL;
    if (!real_pwrite64)
        real_pwrite64 = dlsym(RTLD_NEXT, "pwrite64");

    char path_buf[PATH_MAX] = {0};
    const char *path = get_fd_path(fd, path_buf, sizeof(path_buf));
    
    int is_target = path && is_target_dwg_file(path);
    
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

    DEBUG_LOG("pwrite64加密: 前3字节: %02x %02x %02x ...", data[0], data[1], data[2]);

    ssize_t ret = real_pwrite64(fd, encrypted_buf, count, offset);
    free(encrypted_buf);

    if (ret >= 0) {
        // 标记对应偏移范围在磁盘已加密，避免 msync/munmap 重复加密
        mark_regions_disk_encrypted_for_fd_range(fd, offset, count);
    }

    DEBUG_LOG("pwrite64: 返回 %zd %s", ret, ret < 0 ? strerror(errno) : "");
    return ret;
}

int msync(void *addr, size_t length, int flags) {
    static int (*real_msync)(void *, size_t, int) = NULL;
    if (!real_msync)
        real_msync = dlsym(RTLD_NEXT, "msync");

    DEBUG_LOG("msync: 地址=%p, 长度=%zu, 标志=0x%x", addr, length, flags);

    pthread_mutex_lock(&mmap_mutex);
    int idx = -1;
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == NULL) continue;
        void *reg_start = mmap_regions[i].addr;
        void *reg_end = (char*)reg_start + mmap_regions[i].length;
        // 判断传入的 addr 是否在某个 tracked region 内（以 reg_start 为基准）
        if (addr >= reg_start && addr < reg_end) {
            idx = i;
            break;
        }
    }

    if (idx >= 0) {
        mmap_region_t *region = &mmap_regions[idx];
        // 只有目标文件且已经修改且磁盘未加密时，才进行加密与同步
        if (region->should_decrypt && region->modified && !region->disk_encrypted) {
            DEBUG_LOG("msync: 区域 %p+%zu 需要加密后再同步", region->addr, region->length);
            pthread_mutex_unlock(&mmap_mutex);
            if (safe_encrypt_mmap_region(region->addr, length) != 0) {
                DEBUG_LOG("[警告] msync: 加密失败");
            }
            // 进行真实 msync（加密后）
            int ret = real_msync(addr, length, flags);
            // 解密回内存以保证 CAD 继续读到明文（只有当我们之前解密过内存）
            pthread_mutex_lock(&mmap_mutex);
            if (!mmap_regions[idx].in_memory_encrypted) {
                // 解密内存回明文（注意：这里假设我们能安全解密整个 range）
                safe_decrypt_mmap_region(region->addr, region->length);
            }
            mmap_regions[idx].modified = false;
            pthread_mutex_unlock(&mmap_mutex);
            DEBUG_LOG("msync: 加密并同步完成");
            return ret;
        } else {
            pthread_mutex_unlock(&mmap_mutex);
            int ret = real_msync(addr, length, flags);
            DEBUG_LOG("msync: 无需特殊处理，返回 %d", ret);
            return ret;
        }
    } else {
        pthread_mutex_unlock(&mmap_mutex);
        int ret = real_msync(addr, length, flags);
        DEBUG_LOG("msync: 未跟踪区域，直接调用 real_msync 返回 %d", ret);
        return ret;
    }
}

int mprotect(void *addr, size_t len, int prot) {
    static int (*real_mprotect)(void *, size_t, int) = NULL;
    if (!real_mprotect)
        real_mprotect = dlsym(RTLD_NEXT, "mprotect");
    
    // 如果这个地址属于我们跟踪的 region，更新区域信息
    pthread_mutex_lock(&mmap_mutex);
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == NULL) continue;

        void *reg_start = mmap_regions[i].addr;
        void *reg_end = (char*)reg_start + mmap_regions[i].length;
        if (addr >= reg_start && addr < reg_end) {
            mmap_regions[i].prot = prot;
            if (prot & PROT_WRITE) {
                mmap_regions[i].modified = true;
                // 标记磁盘上的内容和内存不一致，需要在 msync/munmap 时加密
                mmap_regions[i].disk_encrypted = false;
                DEBUG_LOG("标记区域 %p+%zu 为可写 (modified=true, disk_encrypted=false)", addr, len);
            }
            // 不 break，尽量更新所有包含该 addr 的 region
        }
    }
    pthread_mutex_unlock(&mmap_mutex);
    
    return real_mprotect(addr, len, prot);
}

// rename hook：调用真实 rename，再在新路径上加密（如果匹配）
int rename(const char *oldpath, const char *newpath) {
    static int (*real_rename)(const char *, const char *) = NULL;
    if (!real_rename) real_rename = dlsym(RTLD_NEXT, "rename");

    DEBUG_LOG("rename: %s -> %s", oldpath?oldpath:"(null)", newpath?newpath:"(null)");
    int ret = real_rename(oldpath, newpath);

    if (ret == 0 && newpath && is_target_dwg_file(newpath)) {
        // 新路径是目标 DWG，确保磁盘文件被加密（以防它来自临时明文）
        if (encrypt_file_on_disk(newpath) != 0) {
            DEBUG_LOG("rename: 对 newpath 加密失败 %s", newpath);
        }
    }

    return ret;
}

// renameat hook：同理
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    static int (*real_renameat)(int, const char *, int, const char *) = NULL;
    if (!real_renameat) real_renameat = dlsym(RTLD_NEXT, "renameat");

    DEBUG_LOG("renameat: %d:%s -> %d:%s", olddirfd, oldpath?oldpath:"(null)", newdirfd, newpath?newpath:"(null)");
    int ret = real_renameat(olddirfd, oldpath, newdirfd, newpath);

    if (ret == 0 && newpath) {
        // 尝试解析 newpath 相对 newdirfd 到绝对路径，简单处理：若 newdirfd == AT_FDCWD 则直接检查 newpath；
        // 否则我们试图用 /proc/self/fd/<fd> 拼接，但为了稳妥，这里只在 newpath 为绝对路径或 AT_FDCWD 时处理。
        if (newpath[0] == '/' && is_target_dwg_file(newpath)) {
            if (encrypt_file_on_disk(newpath) != 0) {
                DEBUG_LOG("renameat: 对 newpath 加密失败 %s", newpath);
            }
        } else if (newdirfd == AT_FDCWD && is_target_dwg_file(newpath)) {
            if (encrypt_file_on_disk(newpath) != 0) {
                DEBUG_LOG("renameat: 对 newpath 加密失败 %s", newpath);
            }
        } else {
            // 可扩展：解析 newdirfd -> 路径后再拼接处理
            DEBUG_LOG("renameat: 未处理的 newpath (可能为相对): %s (newdirfd=%d)", newpath, newdirfd);
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