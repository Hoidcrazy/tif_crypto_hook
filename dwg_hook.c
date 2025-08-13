// 文件路径: /home/chane/tif_crypto_hook/dwg_hook.c
//
// 编译命令:
//   gcc -shared -fPIC -o libdwg_hook.so dwg_hook.c -ldl -lpthread
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

// ==================== 配置与全局调试 ====================

#define MAX_TRACKED_FD 1024

// 调试标志：控制是否输出调试日志
static int debug_enabled = -1;

/** 初始化调试标志（DWG_HOOK_DEBUG=1 时开启日志） */
static void init_debug_flag(void) {
    if (debug_enabled == -1) {
        const char *env = getenv("DWG_HOOK_DEBUG");
        debug_enabled = (env && strcmp(env, "1") == 0) ? 1 : 0;
    }
}

/** 调试日志输出宏 */
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

// ==================== 目标文件判定（只在 open/openat 时用一次） ====================

/**
 * 判断给定路径是否为需要处理的目标 DWG 文件：
 * 1) 扩展名为 .dwg（不区分大小写）
 * 2) 路径包含 "changed_"
 */
static int is_target_dwg_file(const char *path) {
    if (!path) return 0;

    size_t len = strlen(path);
    if (len < 4) return 0;

    const char *ext = path + len - 4;
    if (strcasecmp(ext, ".dwg") != 0) return 0;

    if (strstr(path, "changed_") == NULL) return 0;

    return 1;
}

// ==================== FD→上下文字典（哈希表） ====================
//
// 设计说明：
// - 在 open/openat 成功后，创建 fd_context_t 并插入哈希表。
// - 之后的 read/pread/write/pwrite/mmap/... 直接按 fd 查询（不再读 /proc/self/fd）。
// - close 时移除上下文。
// - 为避免竞态，所有访问均用全局互斥锁保护。
// - 提供 get_copy 接口，调用方拿到一份独立副本（含 path 的 strdup），用后自行 free。

typedef struct {
    int   is_target;           // 是否目标DWG
    char *path;                // 真实路径（open 时解析）
    bool  should_decrypt;      // 是否需要在读/映射时解密
    bool  disk_encrypted;      // 认为磁盘侧当前为加密态（写入后标记/重命名兜底）
    bool  in_memory_encrypted; // 认为内存侧当前为加密态（解密成功后置 false）
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

/** 插入/更新 FD 上下文（内部复制 path） */
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
}

/** 获取 FD 上下文的拷贝（调用者需要 free(*out).path）。返回 1=成功，0=不存在 */
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

/** 仅更新布尔标记（不改路径） */
static void fd_ctx_update_flags(int fd, bool *disk_encrypted, bool *in_memory_encrypted) {
    pthread_mutex_lock(&fd_table_mutex);
    fd_node_t *n = fd_table[fd_hash(fd)];
    while (n) {
        if (n->fd == fd) {
            if (disk_encrypted)       n->ctx.disk_encrypted = *disk_encrypted;
            if (in_memory_encrypted)  n->ctx.in_memory_encrypted = *in_memory_encrypted;
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
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&fd_table_mutex);
}

// ==================== mmap 区域追踪（保持原有能力） ====================

typedef struct {
    void *addr;                    // 映射起始地址
    size_t length;                 // 映射长度
    int should_decrypt;            // 是否需要解密（映射于目标文件）
    int prot;                      // 原始保护
    int flags;                     // 映射标志
    int fd;                        // 关联 fd
    off_t offset;                  // 文件偏移
    bool modified;                 // 内存是否被修改
    bool in_memory_encrypted;      // 内存是否处于加密态
    bool disk_encrypted;           // 磁盘侧是否加密
} mmap_region_t;

#define MAX_MMAP_REGIONS 256
static mmap_region_t mmap_regions[MAX_MMAP_REGIONS] = {0};
static pthread_mutex_t mmap_mutex = PTHREAD_MUTEX_INITIALIZER;

/** 查找空槽（需已加锁） */
static int find_free_mmap_slot_locked(void) {
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == NULL) return i;
    }
    return -1;
}

/** 按地址所属范围查找 region（读场景下短时加锁） */
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

/** 标记某 fd 的所有 region 为磁盘已加密（write 成功后调用） */
static void mark_regions_disk_encrypted_for_fd(int fd) {
    pthread_mutex_lock(&mmap_mutex);
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr && mmap_regions[i].fd == fd) {
            mmap_regions[i].disk_encrypted = true;
            DEBUG_LOG("标记 region fd=%d addr=%p+%zu 为 disk_encrypted=true",
                      fd, mmap_regions[i].addr, mmap_regions[i].length);
        }
    }
    pthread_mutex_unlock(&mmap_mutex);
}

/** 标记某 fd 在特定偏移覆盖范围内的 region 为磁盘已加密（pwrite 成功后调用） */
static void mark_regions_disk_encrypted_for_fd_range(int fd, off_t offset, size_t count) {
    pthread_mutex_lock(&mmap_mutex);
    off_t write_start = offset;
    off_t write_end   = offset + (off_t)count;
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (!mmap_regions[i].addr || mmap_regions[i].fd != fd) continue;
        off_t reg_start = mmap_regions[i].offset;
        off_t reg_end   = mmap_regions[i].offset + (off_t)mmap_regions[i].length;
        if (!(write_end <= reg_start || write_start >= reg_end)) {
            mmap_regions[i].disk_encrypted = true;
            DEBUG_LOG("标记 region(fd=%d) 偏移覆盖为 disk_encrypted=true (write %ld..%ld overlap %ld..%ld)",
                      fd, (long)write_start, (long)write_end, (long)reg_start, (long)reg_end);
        }
    }
    pthread_mutex_unlock(&mmap_mutex);
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
        // 对目标文件：默认磁盘与内存初始视为加密（后续解密成功会更新内存态）
        mmap_regions[slot].in_memory_encrypted = true;
        mmap_regions[slot].disk_encrypted = should_decrypt ? true : true;
        DEBUG_LOG("[内存映射] 跟踪区域: slot=%d addr=%p len=%zu fd=%d should_decrypt=%d",
                  slot, addr, length, fd, should_decrypt);
    } else {
        DEBUG_LOG("[内存映射] 无可用插槽来跟踪 addr=%p len=%zu", addr, length);
    }
    pthread_mutex_unlock(&mmap_mutex);
}

/** 解除 mmap 区域跟踪 */
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

/** 返回地址对应 region 下标（未加锁，调用方自己控制） */
static int find_mmap_region_index_by_addr(void *addr) {
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == addr) return i;
    }
    return -1;
}

// ==================== 内存页权限/加解密工具 ====================

/** 查询某地址所在映射区域的当前权限（rwx->PROT_*） */
static int get_memory_protection(void *addr) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        DEBUG_LOG("[内存权限] 无法打开/proc/self/maps");
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
    DEBUG_LOG("[内存权限] 地址 %p 权限: %c%c%c (0x%x)",
              addr,
              (protection & PROT_READ) ? 'r' : '-',
              (protection & PROT_WRITE) ? 'w' : '-',
              (protection & PROT_EXEC) ? 'x' : '-',
              protection);
    return protection;
}

/** 对只读映射做“复制-替换”后解密；对可写映射直接 in-place 解密 */
static int safe_decrypt_mmap_region(void *addr, size_t length) {
    if (!addr || length == 0) return -1;

    int orig_prot = get_memory_protection(addr);

    // 只读：使用匿名映射替换
    if ((orig_prot & PROT_WRITE) == 0) {
        DEBUG_LOG("[内存解密] 只读内存区域，使用替换映射策略");
        void *tmp = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (tmp == MAP_FAILED) {
            DEBUG_LOG("[内存解密] 匿名映射创建失败: %s", strerror(errno));
            return -1;
        }
        memcpy(tmp, addr, length);
        unsigned char *p = (unsigned char *)tmp;
        for (size_t i = 0; i < length; ++i) p[i] ^= 0xFF;

        if (munmap(addr, length)) {
            DEBUG_LOG("[内存解密] 解除原映射失败: %s", strerror(errno));
            munmap(tmp, length);
            return -1;
        }
        void *remap = mmap(addr, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
        if (remap != addr) {
            DEBUG_LOG("[内存解密] 重新映射失败: 期望=%p, 实际=%p", addr, remap);
            munmap(tmp, length);
            return -1;
        }
        memcpy(addr, tmp, length);
        munmap(tmp, length);

        if (mprotect(addr, length, orig_prot)) {
            DEBUG_LOG("[内存解密] 恢复权限失败: %s", strerror(errno));
        }
        DEBUG_LOG("[内存解密] 映射替换完成");
        return 0;
    }

    // 可写：直接异或
    if (mprotect(addr, length, PROT_READ | PROT_WRITE) != 0) {
        DEBUG_LOG("[内存解密] mprotect失败: %s (原始权限:0x%x)", strerror(errno), orig_prot);
        return -1;
    }
    unsigned char *data = (unsigned char *)addr;
    for (size_t i = 0; i < length; ++i) data[i] ^= 0xFF;

    if (mprotect(addr, length, orig_prot) != 0) {
        DEBUG_LOG("[内存解密] 恢复权限失败: %s", strerror(errno));
    }
    return 0;
}

/** 对内存区进行安全加密（用于 msync/munmap 前保证落盘是密文） */
static int safe_encrypt_mmap_region(void *addr, size_t length) {
    if (!addr || length == 0) return -1;
    if (mprotect(addr, length, PROT_READ | PROT_WRITE) != 0) {
        DEBUG_LOG("[内存加密] mprotect失败: %s", strerror(errno));
        return -1;
    }
    unsigned char *data = (unsigned char *)addr;
    for (size_t i = 0; i < length; ++i) data[i] ^= 0xFF;
    if (mprotect(addr, length, PROT_READ) != 0) {
        DEBUG_LOG("[内存加密] 恢复权限失败: %s", strerror(errno));
    }
    // 同步更新 region 状态
    pthread_mutex_lock(&mmap_mutex);
    int idx = find_mmap_region_index_by_addr(addr);
    if (idx >= 0) {
        mmap_regions[idx].in_memory_encrypted = true;
        mmap_regions[idx].disk_encrypted = true;
        mmap_regions[idx].modified = false;
    }
    pthread_mutex_unlock(&mmap_mutex);
    return 0;
}

// ==================== 文件兜底加密（rename 后） ====================

#define ENCRYPT_CHUNK (64*1024)

/** 粗略判断是否“看起来像明文 DWG”（仅检查前4字节 "AC1*"） */
static int file_looks_plain_dwg(int fd) {
    unsigned char hdr[8] = {0};
    ssize_t r = pread(fd, hdr, sizeof(hdr), 0);
    if (r <= 0) return 0;
    if (hdr[0] == 'A' && hdr[1] == 'C' && hdr[2] == '1') return 1;
    return 0;
}

/** 将磁盘上的文件整体按 0xFF 异或加密（避免明文落盘） */
static int encrypt_file_on_disk(const char *path) {
    if (!path) return -1;
    int fd = open(path, O_RDWR);
    if (fd < 0) {
        DEBUG_LOG("encrypt_file_on_disk: 打开失败 %s: %s", path, strerror(errno));
        return -1;
    }
    if (!file_looks_plain_dwg(fd)) {
        close(fd);
        DEBUG_LOG("encrypt_file_on_disk: 文件看起来非明文或已加密，跳过: %s", path);
        return 0;
    }
    off_t size = lseek(fd, 0, SEEK_END);
    if (size == (off_t)-1) {
        DEBUG_LOG("encrypt_file_on_disk: lseek失败 %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    unsigned char *buf = (unsigned char *)malloc(ENCRYPT_CHUNK);
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
    fsync(fd);
    close(fd);
    DEBUG_LOG("encrypt_file_on_disk: 完成对文件加密: %s (大小=%ld)", path, (long)size);
    return 0;
}

// ==================== Hook 实现：open/openat 建立上下文 ====================

int openat(int dirfd, const char *pathname, int flags, ...) {
    static int (*real_openat)(int, const char *, int, ...) = NULL;
    if (!real_openat) real_openat = dlsym(RTLD_NEXT, "openat");

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    int fd = (flags & O_CREAT) ? real_openat(dirfd, pathname, flags, mode)
                               : real_openat(dirfd, pathname, flags);
    if (fd >= 0) {
        // 构造上下文并写入字典
        char *resolved = NULL;
        if (pathname) {
            resolved = realpath(pathname, NULL);
            if (!resolved) resolved = strdup(pathname);
        }
        fd_context_t ctx = {0};
        ctx.path = resolved;
        ctx.is_target = is_target_dwg_file(resolved);
        ctx.should_decrypt = ctx.is_target;
        ctx.disk_encrypted = ctx.is_target;       // 认为磁盘初始是密文
        ctx.in_memory_encrypted = ctx.is_target;  // 认为内存初始是密文
        fd_ctx_set(fd, &ctx);

        DEBUG_LOG("openat: fd=%d 路径='%s' flags=0x%x%s -> is_target=%d",
                  fd, resolved ? resolved : "(null)", flags, (flags & O_CREAT) ? " | O_CREAT" : "", ctx.is_target);
        free(resolved);  // fd_ctx_set 内部已复制
    } else {
        DEBUG_LOG("openat 失败: dirfd=%d, 路径='%s', 错误=%d (%s)",
                  dirfd, pathname ? pathname : "(空)", errno, strerror(errno));
    }
    return fd;
}

int open(const char *pathname, int flags, ...) {
    static int (*real_open)(const char *, int, ...) = NULL;
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    int fd = (flags & O_CREAT) ? real_open(pathname, flags, mode)
                               : real_open(pathname, flags);
    if (fd >= 0) {
        char *resolved = NULL;
        if (pathname) {
            resolved = realpath(pathname, NULL);
            if (!resolved) resolved = strdup(pathname);
        }
        fd_context_t ctx = {0};
        ctx.path = resolved;
        ctx.is_target = is_target_dwg_file(resolved);
        ctx.should_decrypt = ctx.is_target;
        ctx.disk_encrypted = ctx.is_target;
        ctx.in_memory_encrypted = ctx.is_target;
        fd_ctx_set(fd, &ctx);

        DEBUG_LOG("open: fd=%d 路径='%s' flags=0x%x%s -> is_target=%d",
                  fd, resolved ? resolved : "(null)", flags, (flags & O_CREAT) ? " | O_CREAT" : "", ctx.is_target);
        free(resolved);
    } else {
        DEBUG_LOG("open 失败: 路径='%s', 错误=%d (%s)",
                  pathname ? pathname : "(空)", errno, strerror(errno));
    }
    return fd;
}

// ==================== Hook：读取时透明解密 ====================

ssize_t pread64(int fd, void *buf, size_t count, off_t offset) {
    static ssize_t (*real_pread64)(int, void *, size_t, off_t) = NULL;
    if (!real_pread64) real_pread64 = dlsym(RTLD_NEXT, "pread64");

    ssize_t ret = real_pread64(fd, buf, count, offset);
    if (ret <= 0) return ret;

    fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    if (!fd_ctx_get_copy(fd, &ctx)) return ret;

    if (ctx.is_target && ctx.should_decrypt) {
        unsigned char *data = (unsigned char *)buf;
        for (ssize_t i = 0; i < ret; ++i) data[i] ^= 0xFF;
        DEBUG_LOG("pread64 解密: fd=%d off=%ld size=%zd 路径=%s", fd, (long)offset, ret, ctx.path ? ctx.path : "(?)");
    }
    free(ctx.path);
    return ret;
}

ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real_read)(int, void *, size_t) = NULL;
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");

    ssize_t ret = real_read(fd, buf, count);
    if (ret <= 0) return ret;

    fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    if (!fd_ctx_get_copy(fd, &ctx)) return ret;

    if (ctx.is_target && ctx.should_decrypt) {
        unsigned char *data = (unsigned char *)buf;
        for (ssize_t i = 0; i < ret; ++i) data[i] ^= 0xFF;
        DEBUG_LOG("read 解密: fd=%d size=%zd 路径=%s", fd, ret, ctx.path ? ctx.path : "(?)");
    }
    free(ctx.path);
    return ret;
}

// ==================== Hook：mmap/mmap64 透明解密、写前加密保障 ====================

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    static void *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
    if (!real_mmap) real_mmap = dlsym(RTLD_NEXT, "mmap");

    void *ptr = real_mmap(addr, length, prot, flags, fd, offset);
    if (ptr == MAP_FAILED) return ptr;

    int should_decrypt = 0;
    if (fd >= 0) {
        fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
        if (fd_ctx_get_copy(fd, &ctx)) {
            should_decrypt = (ctx.is_target && ctx.should_decrypt) ? 1 : 0;
            DEBUG_LOG("mmap: fd=%d 路径=%s should_decrypt=%d addr=%p len=%zu",
                      fd, ctx.path ? ctx.path : "(?)", should_decrypt, ptr, length);
            free(ctx.path);
        }
    }

    track_mmap_region(ptr, length, should_decrypt, prot, flags, fd, offset);

    if (should_decrypt) {
        if (safe_decrypt_mmap_region(ptr, length) == 0) {
            // 更新 region 的内存态为“已解密”
            pthread_mutex_lock(&mmap_mutex);
            int idx = find_mmap_region_index_by_addr(ptr);
            if (idx >= 0) mmap_regions[idx].in_memory_encrypted = false;
            pthread_mutex_unlock(&mmap_mutex);
        } else {
            DEBUG_LOG("[警告] mmap 解密失败，可能未解密");
        }
    }
    return ptr;
}

void *mmap64(void *addr, size_t length, int prot, int flags, int fd, off64_t offset) {
    static void *(*real_mmap64)(void *, size_t, int, int, int, off64_t) = NULL;
    if (!real_mmap64) real_mmap64 = dlsym(RTLD_NEXT, "mmap64");

    void *ptr = real_mmap64(addr, length, prot, flags, fd, offset);
    if (ptr == MAP_FAILED) return ptr;

    int should_decrypt = 0;
    if (fd >= 0) {
        fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
        if (fd_ctx_get_copy(fd, &ctx)) {
            should_decrypt = (ctx.is_target && ctx.should_decrypt) ? 1 : 0;
            DEBUG_LOG("mmap64: fd=%d 路径=%s should_decrypt=%d addr=%p len=%zu",
                      fd, ctx.path ? ctx.path : "(?)", should_decrypt, ptr, length);
            free(ctx.path);
        }
    }

    track_mmap_region(ptr, length, should_decrypt, prot, flags, fd, (off_t)offset);

    if (should_decrypt) {
        if (safe_decrypt_mmap_region(ptr, length) == 0) {
            pthread_mutex_lock(&mmap_mutex);
            int idx = find_mmap_region_index_by_addr(ptr);
            if (idx >= 0) mmap_regions[idx].in_memory_encrypted = false;
            pthread_mutex_unlock(&mmap_mutex);
        } else {
            DEBUG_LOG("[警告] mmap64 解密失败，可能未解密");
        }
    }
    return ptr;
}

int munmap(void *addr, size_t length) {
    static int (*real_munmap)(void *, size_t) = NULL;
    if (!real_munmap) real_munmap = dlsym(RTLD_NEXT, "munmap");

    // 在解除映射前，若是目标且被修改且磁盘未加密，则先加密
    pthread_mutex_lock(&mmap_mutex);
    int idx = -1;
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == addr) { idx = i; break; }
    }
    mmap_region_t region_copy = {0};
    if (idx >= 0) region_copy = mmap_regions[idx];
    pthread_mutex_unlock(&mmap_mutex);

    if (idx >= 0 && region_copy.should_decrypt && region_copy.modified && !region_copy.disk_encrypted) {
        DEBUG_LOG("munmap: 需要先加密再解除映射 %p+%zu", addr, length);
        if (safe_encrypt_mmap_region(addr, length) != 0) {
            DEBUG_LOG("[警告] munmap: 加密失败，可能导致明文落盘");
        } else {
            if (region_copy.fd >= 0) msync(addr, length, MS_SYNC);
        }
    }

    int ret = real_munmap(addr, length);
    if (ret == 0) untrack_mmap_region(addr);
    return ret;
}

// 在 mprotect 发生写权限赋予时，标记 region 已被修改，需在 msync/munmap 时保证落盘密文
int mprotect(void *addr, size_t len, int prot) {
    static int (*real_mprotect)(void *, size_t, int) = NULL;
    if (!real_mprotect) real_mprotect = dlsym(RTLD_NEXT, "mprotect");

    pthread_mutex_lock(&mmap_mutex);
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (!mmap_regions[i].addr) continue;
        char *start = (char *)mmap_regions[i].addr;
        char *end   = start + mmap_regions[i].length;
        if ((char *)addr >= start && (char *)addr < end) {
            mmap_regions[i].prot = prot;
            if (prot & PROT_WRITE) {
                mmap_regions[i].modified = true;
                mmap_regions[i].disk_encrypted = false;
                DEBUG_LOG("mprotect: 标记 region %p+%zu modified=true disk_encrypted=false", addr, len);
            }
        }
    }
    pthread_mutex_unlock(&mmap_mutex);
    return real_mprotect(addr, len, prot);
}

int msync(void *addr, size_t length, int flags) {
    static int (*real_msync)(void *, size_t, int) = NULL;
    if (!real_msync) real_msync = dlsym(RTLD_NEXT, "msync");

    // 若目标 region 已修改且磁盘未加密，先加密内存再同步
    pthread_mutex_lock(&mmap_mutex);
    int idx = -1;
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (!mmap_regions[i].addr) continue;
        char *start = (char *)mmap_regions[i].addr;
        char *end   = start + mmap_regions[i].length;
        if ((char *)addr >= start && (char *)addr < end) { idx = i; break; }
    }
    mmap_region_t region_copy = {0};
    if (idx >= 0) region_copy = mmap_regions[idx];
    pthread_mutex_unlock(&mmap_mutex);

    if (idx >= 0 && region_copy.should_decrypt && region_copy.modified && !region_copy.disk_encrypted) {
        DEBUG_LOG("msync: 需要先对内存加密再同步 %p+%zu", addr, length);
        if (safe_encrypt_mmap_region(region_copy.addr, region_copy.length) != 0) {
            DEBUG_LOG("[警告] msync: 内存加密失败");
        }
        int ret = real_msync(addr, length, flags);
        // 若我们之前将内存加密，为保证 CAD 后续可继续读明文，可选：再解密回内存
        pthread_mutex_lock(&mmap_mutex);
        if (idx >= 0 && !mmap_regions[idx].in_memory_encrypted) {
            safe_decrypt_mmap_region(region_copy.addr, region_copy.length);
        }
        mmap_regions[idx].modified = false;
        pthread_mutex_unlock(&mmap_mutex);
        return ret;
    }
    return real_msync(addr, length, flags);
}

// ==================== Hook：写入时强制密文落盘 ====================

ssize_t write(int fd, const void *buf, size_t count) {
    static ssize_t (*real_write)(int, const void *, size_t) = NULL;
    if (!real_write) real_write = dlsym(RTLD_NEXT, "write");

    if (count == 0 || !buf) return real_write(fd, buf, count);

    fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    if (!fd_ctx_get_copy(fd, &ctx)) return real_write(fd, buf, count);

    ssize_t ret;
    if (!(ctx.is_target)) {
        ret = real_write(fd, buf, count);
    } else {
        // 目标文件：加密后写入，保证磁盘始终保存密文
        void *tmp = malloc(count);
        if (!tmp) { free(ctx.path); errno = ENOMEM; return -1; }
        memcpy(tmp, buf, count);
        unsigned char *p = (unsigned char *)tmp;
        for (size_t i = 0; i < count; ++i) p[i] ^= 0xFF;

        ret = real_write(fd, tmp, count);
        free(tmp);
        if (ret >= 0) {
            // 标记 fd 侧与所有 region 的磁盘为加密
            bool dk = true;
            fd_ctx_update_flags(fd, &dk, NULL);
            mark_regions_disk_encrypted_for_fd(fd);
        }
    }
    free(ctx.path);
    return ret;
}

ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset) {
    static ssize_t (*real_pwrite64)(int, const void *, size_t, off_t) = NULL;
    if (!real_pwrite64) real_pwrite64 = dlsym(RTLD_NEXT, "pwrite64");

    if (count == 0 || !buf) return real_pwrite64(fd, buf, count, offset);

    fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    if (!fd_ctx_get_copy(fd, &ctx)) return real_pwrite64(fd, buf, count, offset);

    ssize_t ret;
    if (!(ctx.is_target)) {
        ret = real_pwrite64(fd, buf, count, offset);
    } else {
        void *tmp = malloc(count);
        if (!tmp) { free(ctx.path); errno = ENOMEM; return -1; }
        memcpy(tmp, buf, count);
        unsigned char *p = (unsigned char *)tmp;
        for (size_t i = 0; i < count; ++i) p[i] ^= 0xFF;

        ret = real_pwrite64(fd, tmp, count, offset);
        free(tmp);
        if (ret >= 0) {
            bool dk = true;
            fd_ctx_update_flags(fd, &dk, NULL);
            mark_regions_disk_encrypted_for_fd_range(fd, offset, count);
        }
    }
    free(ctx.path);
    return ret;
}

// ==================== Hook：rename/renameat 后兜底加密 ====================

int rename(const char *oldpath, const char *newpath) {
    static int (*real_rename)(const char *, const char *) = NULL;
    if (!real_rename) real_rename = dlsym(RTLD_NEXT, "rename");

    int ret = real_rename(oldpath, newpath);
    if (ret == 0 && newpath && is_target_dwg_file(newpath)) {
        if (encrypt_file_on_disk(newpath) != 0) {
            DEBUG_LOG("rename: 对 newpath 加密失败 %s", newpath);
        }
    }
    return ret;
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    static int (*real_renameat)(int, const char *, int, const char *) = NULL;
    if (!real_renameat) real_renameat = dlsym(RTLD_NEXT, "renameat");

    int ret = real_renameat(olddirfd, oldpath, newdirfd, newpath);
    if (ret == 0 && newpath) {
        if (newpath[0] == '/' && is_target_dwg_file(newpath)) {
            if (encrypt_file_on_disk(newpath) != 0) {
                DEBUG_LOG("renameat: 对 newpath 加密失败 %s", newpath);
            }
        } else if (newdirfd == AT_FDCWD && is_target_dwg_file(newpath)) {
            if (encrypt_file_on_disk(newpath) != 0) {
                DEBUG_LOG("renameat: 对 newpath 加密失败 %s", newpath);
            }
        } else {
            DEBUG_LOG("renameat: 未处理的相对路径场景 newpath=%s newdirfd=%d", newpath ? newpath : "(null)", newdirfd);
        }
    }
    return ret;
}

// ==================== Hook：close 清理上下文 ====================

int close(int fd) {
    static int (*real_close)(int) = NULL;
    if (!real_close) real_close = dlsym(RTLD_NEXT, "close");

    // 日志需要路径，先拷贝
    fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    int have = fd_ctx_get_copy(fd, &ctx);

    int ret = real_close(fd);
    if (ret == 0) {
        if (have) {
            DEBUG_LOG("close: fd=%d 路径='%s' is_target=%d", fd, ctx.path ? ctx.path : "(?)", ctx.is_target);
        } else {
            DEBUG_LOG("close: fd=%d (无上下文)", fd);
        }
        fd_ctx_remove(fd);
    } else {
        DEBUG_LOG("close 失败: fd=%d, 错误=%d (%s)", fd, errno, strerror(errno));
    }
    if (have) free(ctx.path);
    return ret;
}
