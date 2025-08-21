// 文件路径: /home/chane/tif_crypto_hook/dwg_hook.c
//
// 编译命令:
//   gcc -shared -fPIC -o libdwg_hook.so dwg_hook.c -ldl -lpthread
//
// 使用方法:
//   export DWG_HOOK_DEBUG=1
//   LD_PRELOAD=/home/chane/tif_crypto_hook/libdwg_hook.so /opt/apps/zwcad2025/ZWCADRUN.sh

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
#include <ctype.h>
#include <time.h>
#include <stdint.h>

// ==================== 可调参数 ====================

#define WRITE_BLOCK_SIZE              (512 * 1024)         // 写入分块大小：512KB
#define MEMORY_CRYPT_BLOCK_SIZE       (2UL * 1024 * 1024)  // 内存分块大小：2MB
#define MAX_PATH_LEN                  4096
#define MAX_MMAP_REGIONS              2048                 // 适配更多映射
#define LOG_HEX_PREVIEW_BYTES         48

// ==================== 日志与工具 ====================

static int g_debug_enabled = -1;

static int is_debug_enabled(void) {
    if (g_debug_enabled == -1) {
        const char *e = getenv("DWG_HOOK_DEBUG");
        g_debug_enabled = (e && *e && strcmp(e, "0") != 0) ? 1 : 0;
    }
    return g_debug_enabled;
}

static void debug_log(const char *fmt, ...) {
    if (!is_debug_enabled()) return;
    static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&log_mutex);
    FILE *fp = fopen("/tmp/dwg_hook.log", "a");
    if (fp) {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(fp, fmt, ap);
        fprintf(fp, "\n");
        va_end(ap);
        fclose(fp);
    }
    pthread_mutex_unlock(&log_mutex);
}
#define DEBUG_LOG(...) do { debug_log(__VA_ARGS__); } while(0)

static void log_hex_preview(const char *tag, const unsigned char *buf, size_t n) {
    if (!is_debug_enabled() || !buf || n == 0) return;
    size_t show = n < LOG_HEX_PREVIEW_BYTES ? n : LOG_HEX_PREVIEW_BYTES;
    char line[LOG_HEX_PREVIEW_BYTES * 3 + 64];
    char *p = line;
    int written = snprintf(p, sizeof(line), "%s: (%zu bytes) ", tag, n);
    p += (written > 0) ? written : 0;
    for (size_t i = 0; i < show && (p - line + 3) < (int)sizeof(line); i++) {
        p += snprintf(p, line + sizeof(line) - p, "%02X ", buf[i]);
    }
    DEBUG_LOG("%s", line);
}

// ======= 页尺寸缓存与页对齐 =======
static inline size_t page_size_cached(void) {
    static size_t ps = 0;
    if (!ps) { ps = (size_t)sysconf(_SC_PAGESIZE); if (ps == 0) ps = 4096; }
    return ps;
}
static inline void align_to_pages(void *addr, size_t len, void **out_start, size_t *out_len) {
    size_t ps = page_size_cached();
    uintptr_t p = (uintptr_t)addr;
    uintptr_t start = p & ~(ps - 1);
    uintptr_t end   = (p + len + ps - 1) & ~(ps - 1);
    *out_start = (void*)start;
    *out_len   = (size_t)(end - start);
}

// ==================== 文件上下文追踪 ====================

typedef struct fd_context_s {
    int   fd;
    char *path;
    int   is_target;   // 目标 DWG
    int   is_tmp;      // 临时/缓存文件
    struct fd_context_s *next;
} fd_context_t;

static pthread_mutex_t fd_table_mutex = PTHREAD_MUTEX_INITIALIZER;
static fd_context_t *fd_table = NULL;

static int is_dwg_path(const char *path) {
    if (!path) return 0;
    const char *dot = strrchr(path, '.');
    if (!dot) return 0;
    if (strcasecmp(dot, ".dwg") != 0) return 0;
    if (strstr(path, ".tmp") || strstr(path, ".TMP") || strstr(path, "~") ||
        strstr(path, "temp") || strstr(path, "TEMP") || strstr(path, "autosave") ||
        strstr(path, ".bak") || strstr(path, ".sv$")) {
        return 0;
    }
    return 1;
}

static void fd_ctx_add(int fd, const char *path) {
    if (fd < 0) return;
    pthread_mutex_lock(&fd_table_mutex);
    fd_context_t *node = (fd_context_t *)calloc(1, sizeof(fd_context_t));
    if (!node) { pthread_mutex_unlock(&fd_table_mutex); return; }
    node->fd = fd;
    if (path) node->path = strdup(path);
    node->is_target = is_dwg_path(path);
    node->is_tmp = (!node->is_target && path &&
                    (strstr(path, ".tmp") || strstr(path, "~") || strstr(path, "temp")));
    node->next = fd_table;
    fd_table = node;
    DEBUG_LOG("fd_ctx_add: fd=%d, path=%s, is_target=%d, is_tmp=%d",
              fd, node->path ? node->path : "(null)", node->is_target, node->is_tmp);
    pthread_mutex_unlock(&fd_table_mutex);
}

static void fd_ctx_remove(int fd) {
    pthread_mutex_lock(&fd_table_mutex);
    fd_context_t **pp = &fd_table;
    while (*pp) {
        if ((*pp)->fd == fd) {
            fd_context_t *dead = *pp;
            *pp = (*pp)->next;
            if (dead->path) free(dead->path);
            free(dead);
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&fd_table_mutex);
}

static int fd_ctx_get_copy(int fd, fd_context_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&fd_table_mutex);
    fd_context_t *p = fd_table;
    while (p) {
        if (p->fd == fd) {
            out->fd = p->fd;
            out->is_target = p->is_target;
            out->is_tmp = p->is_tmp;
            if (p->path) out->path = strdup(p->path);
            pthread_mutex_unlock(&fd_table_mutex);
            return 1;
        }
        p = p->next;
    }
    pthread_mutex_unlock(&fd_table_mutex);
    return 0;
}

static void fd_ctx_update_flags(int fd, const int *is_target, const int *is_tmp) {
    pthread_mutex_lock(&fd_table_mutex);
    fd_context_t *p = fd_table;
    while (p) {
        if (p->fd == fd) {
            if (is_target) p->is_target = *is_target;
            if (is_tmp)    p->is_tmp    = *is_tmp;
            break;
        }
        p = p->next;
    }
    pthread_mutex_unlock(&fd_table_mutex);
}

// ==================== 内存映射追踪 ====================

typedef struct {
    void *addr;
    size_t length;
    int should_decrypt;     // 该映射是否需要保持明文
    int prot;               // 原始保护
    int flags;
    int fd;
    off_t offset;
    bool modified;          // 是否被写路径修改
} mmap_region_t;

static mmap_region_t mmap_regions[MAX_MMAP_REGIONS];
static pthread_mutex_t mmap_mutex = PTHREAD_MUTEX_INITIALIZER;

static int find_free_mmap_slot_locked(void) {
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == NULL) return i;
    }
    return -1;
}

static mmap_region_t *find_mmap_region_containing(void *addr) {
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (!mmap_regions[i].addr) continue;
        char *start = (char *)mmap_regions[i].addr;
        char *end   = start + mmap_regions[i].length;
        if ((char *)addr >= start && (char *)addr < end) {
            return &mmap_regions[i];
        }
    }
    return NULL;
}

static void mark_fd_mmaps_modified(int fd) {
    if (fd < 0) return;
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr && mmap_regions[i].fd == fd) {
            mmap_regions[i].modified = true;
        }
    }
}

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
        DEBUG_LOG("mmap区域跟踪成功: slot=%d, addr=%p, len=%zu, fd=%d, should_decrypt=%s, flags=0x%x",
                  slot, addr, length, fd, should_decrypt ? "是" : "否", flags);
    } else {
        DEBUG_LOG("警告: 无可用mmap插槽来跟踪 addr=%p len=%zu", addr, length);
    }
    pthread_mutex_unlock(&mmap_mutex);
}

static void untrack_mmap_region(void *addr, size_t length) {
    pthread_mutex_lock(&mmap_mutex);
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == addr && mmap_regions[i].length == length) {
            DEBUG_LOG("取消跟踪mmap区域: addr=%p len=%zu fd=%d", mmap_regions[i].addr, mmap_regions[i].length, mmap_regions[i].fd);
            memset(&mmap_regions[i], 0, sizeof(mmap_regions[i]));
            break;
        }
    }
    pthread_mutex_unlock(&mmap_mutex);
}

// ==================== XOR（加速版） ====================

static void xor_encrypt_decrypt_fast(unsigned char *data, size_t size) {
    size_t i = 0;
    const uint64_t key64 = 0xFFFFFFFFFFFFFFFFULL;
    for (; i + sizeof(uint64_t) <= size; i += sizeof(uint64_t)) {
        uint64_t *p = (uint64_t *)(data + i);
        *p ^= key64;
    }
    for (; i < size; ++i) data[i] ^= 0xFF;
}

// ==================== 分块内存加/解密（页对齐 + mprotect） ====================

static int chunked_memory_crypt(void *addr, size_t length, const char *operation, int restore_prot) {
    if (!addr || length == 0) return -1;

    unsigned char *ptr = (unsigned char *)addr;
    size_t processed = 0;
    const size_t report_every = MEMORY_CRYPT_BLOCK_SIZE * 32; // ~64MB

    while (processed < length) {
        size_t chunk_size = (length - processed > MEMORY_CRYPT_BLOCK_SIZE)
                          ? MEMORY_CRYPT_BLOCK_SIZE
                          : (length - processed);

        void *sub_start = NULL; size_t sub_len = 0;
        align_to_pages(ptr + processed, chunk_size, &sub_start, &sub_len);
        if (mprotect(sub_start, sub_len, PROT_READ | PROT_WRITE) != 0) {
            DEBUG_LOG("mprotect 写失败: %p + %zu, 错误: %s", sub_start, sub_len, strerror(errno));
            return -1;
        }

        xor_encrypt_decrypt_fast(ptr + processed, chunk_size);

        if (mprotect(sub_start, sub_len, restore_prot) != 0) {
            DEBUG_LOG("mprotect 恢复失败: %p + %zu, 错误: %s", sub_start, sub_len, strerror(errno));
        }

        processed += chunk_size;

        if ((processed % report_every) == 0 || processed == length) {
            double pct = (double)processed * 100.0 / (double)length;
            DEBUG_LOG("%s进度: %zu / %zu (%.1f%%)", operation, processed, length, pct);
        }
        if (processed < length) sched_yield();
    }
    return 0;
}

static int safe_decrypt_memory_with_prot(void *addr, size_t length, int restore_prot) {
    if (length <= 4096) log_hex_preview("内存解密前", (unsigned char *)addr, length);
    int r = chunked_memory_crypt(addr, length, "解密", restore_prot);
    if (r == 0 && length <= 4096) log_hex_preview("内存解密后", (unsigned char *)addr, length);
    return r;
}
static int safe_encrypt_memory_with_prot(void *addr, size_t length, int restore_prot) {
    if (length <= 4096) log_hex_preview("内存加密前", (unsigned char *)addr, length);
    int r = chunked_memory_crypt(addr, length, "加密", restore_prot);
    if (r == 0 && length <= 4096) log_hex_preview("内存加密后", (unsigned char *)addr, length);
    return r;
}

// ==================== TLS 分块缓冲 ====================

static unsigned char *get_tls_chunk_buf(size_t want, size_t *cap) {
    static __thread unsigned char *buf = NULL;
    static __thread size_t buf_cap = 0;
    if (buf_cap < want) {
        size_t new_cap = want;
        size_t step = WRITE_BLOCK_SIZE;
        if (new_cap % step) new_cap = ((new_cap / step) + 1) * step;
        unsigned char *nb = (unsigned char*)realloc(buf, new_cap);
        if (!nb) return NULL;
        buf = nb; buf_cap = new_cap;
    }
    if (cap) *cap = buf_cap;
    return buf;
}

// ==================== open/close 系列 ====================

static char *dup_path_from_fd(int fd) {
    if (fd < 0) return NULL;
    char linkpath[64];
    char path[MAX_PATH_LEN];
    snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(linkpath, path, sizeof(path) - 1);
    if (n < 0) return NULL;
    path[n] = '\0';
    return strdup(path);
}

int open(const char *pathname, int flags, ...) {
    static int (*real_open)(const char *, int, mode_t) = NULL;
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
        DEBUG_LOG("open Hook已加载: real_open=%p", real_open);
    }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    int fd = real_open(pathname, flags, mode);
    if (fd >= 0) fd_ctx_add(fd, pathname);
    return fd;
}

int open64(const char *pathname, int flags, ...) {
    static int (*real_open64)(const char *, int, mode_t) = NULL;
    if (!real_open64) {
        real_open64 = dlsym(RTLD_NEXT, "open64");
        DEBUG_LOG("open64 Hook已加载: real_open64=%p", real_open64);
    }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    int fd = real_open64(pathname, flags, mode);
    if (fd >= 0) fd_ctx_add(fd, pathname);
    return fd;
}

int creat(const char *pathname, mode_t mode) {
    static int (*real_creat)(const char *, mode_t) = NULL;
    if (!real_creat) {
        real_creat = dlsym(RTLD_NEXT, "creat");
        DEBUG_LOG("creat Hook已加载: real_creat=%p", real_creat);
    }
    int fd = real_creat(pathname, mode);
    if (fd >= 0) fd_ctx_add(fd, pathname);
    return fd;
}

int close(int fd) {
    static int (*real_close)(int) = NULL;
    if (!real_close) {
        real_close = dlsym(RTLD_NEXT, "close");
        DEBUG_LOG("close Hook已加载: real_close=%p", real_close);
    }
    fd_ctx_remove(fd);
    return real_close(fd);
}

// ==================== read/fread Hook（按需解密） ====================

ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real_read)(int, void *, size_t) = NULL;
    if (!real_read) {
        real_read = dlsym(RTLD_NEXT, "read");
        DEBUG_LOG("read Hook已加载: real_read=%p", real_read);
    }

    ssize_t ret = real_read(fd, buf, count);
    if (ret <= 0 || !buf) return ret;

    fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    if (!fd_ctx_get_copy(fd, &ctx)) return ret;

    if (ctx.is_target) {
        DEBUG_LOG("=====【read Hook】fd=%d, 文件=%s, 字节=%zd", fd, ctx.path ? ctx.path : "未知", ret);
        if ((size_t)ret <= 4096) log_hex_preview("解密前数据", (unsigned char *)buf, ret);
        xor_encrypt_decrypt_fast((unsigned char *)buf, ret);
        if ((size_t)ret <= 4096) log_hex_preview("解密后数据", (unsigned char *)buf, ret);
    }
    free(ctx.path);
    return ret;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    static size_t (*real_fread)(void *, size_t, size_t, FILE *) = NULL;
    if (!real_fread) {
        real_fread = dlsym(RTLD_NEXT, "fread");
        DEBUG_LOG("fread Hook已加载: real_fread=%p", real_fread);
    }

    size_t ret = real_fread(ptr, size, nmemb, stream);
    if (ret == 0 || !ptr) return ret;

    int fd = fileno(stream);
    if (fd >= 0) {
        fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
        if (fd_ctx_get_copy(fd, &ctx)) {
            if (ctx.is_target) {
                size_t total = ret * size;
                DEBUG_LOG("=====【fread Hook】fd=%d, 文件=%s, 字节=%zu", fd, ctx.path ? ctx.path : "未知", total);
                if (total <= 4096) log_hex_preview("fread解密前", (unsigned char *)ptr, total);
                xor_encrypt_decrypt_fast((unsigned char *)ptr, total);
                if (total <= 4096) log_hex_preview("fread解密后", (unsigned char *)ptr, total);
            }
            free(ctx.path);
        }
    }
    return ret;
}

// ==================== 写入 Hook（分块加密并写 + TLS 缓冲） ====================

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
        DEBUG_LOG("=====【write Hook】文件=%s, 大小=%zu", ctx.path ? ctx.path : "未知", count);
        if (count <= 4096) log_hex_preview("加密前", (const unsigned char *)buf, count);

        ssize_t total_written = 0;
        const unsigned char *src = (const unsigned char *)buf;

        while (total_written < (ssize_t)count) {
            size_t chunk = (count - total_written > WRITE_BLOCK_SIZE) ? WRITE_BLOCK_SIZE : (count - total_written);
            unsigned char *tmp = get_tls_chunk_buf(chunk, NULL);
            if (!tmp) { errno = ENOMEM; ret = -1; goto out; }

            memcpy(tmp, src + total_written, chunk);
            xor_encrypt_decrypt_fast(tmp, chunk);

            ssize_t n = real_write(fd, tmp, chunk);
            if (n <= 0) { ret = (n == 0 ? total_written : n); goto out; }
            total_written += n;

            if ((total_written % (WRITE_BLOCK_SIZE * 16)) == 0 || (size_t)total_written == count) {
                double pct = (double)total_written * 100.0 / (double)count;
                DEBUG_LOG("write进度: %zd / %zu (%.1f%%)", total_written, count, pct);
            }
        }
        ret = total_written;
        mark_fd_mmaps_modified(fd);
        { int t = 1; fd_ctx_update_flags(fd, &t, NULL); }

    out:
        ;
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
        DEBUG_LOG("=====【pwrite64 Hook】文件=%s, 偏移=%ld, 大小=%zu", ctx.path ? ctx.path : "未知", (long)offset, count);
        if (count <= 4096) log_hex_preview("pwrite64加密前", (const unsigned char *)buf, count);

        ssize_t total_written = 0;
        const unsigned char *src = (const unsigned char *)buf;
        off_t off = offset;

        while (total_written < (ssize_t)count) {
            size_t chunk = (count - total_written > WRITE_BLOCK_SIZE) ? WRITE_BLOCK_SIZE : (count - total_written);
            unsigned char *tmp = get_tls_chunk_buf(chunk, NULL);
            if (!tmp) { errno = ENOMEM; ret = -1; goto out; }

            memcpy(tmp, src + total_written, chunk);
            xor_encrypt_decrypt_fast(tmp, chunk);

            ssize_t n = real_pwrite64(fd, tmp, chunk, off);
            if (n <= 0) { ret = (n == 0 ? total_written : n); goto out; }
            total_written += n;
            off += n;

            if ((total_written % (WRITE_BLOCK_SIZE * 16)) == 0 || (size_t)total_written == count) {
                double pct = (double)total_written * 100.0 / (double)count;
                DEBUG_LOG("pwrite64进度: %zd / %zu (%.1f%%)", total_written, count, pct);
            }
        }
        ret = total_written;
        mark_fd_mmaps_modified(fd);
        { int t = 1; fd_ctx_update_flags(fd, &t, NULL); }

    out:
        ;
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
        DEBUG_LOG("=====【pwrite Hook】文件=%s, 偏移=%ld, 大小=%zu", ctx.path ? ctx.path : "未知", (long)offset, count);
        if (count <= 4096) log_hex_preview("pwrite加密前", (const unsigned char *)buf, count);

        ssize_t total_written = 0;
        const unsigned char *src = (const unsigned char *)buf;
        off_t off = offset;

        while (total_written < (ssize_t)count) {
            size_t chunk = (count - total_written > WRITE_BLOCK_SIZE) ? WRITE_BLOCK_SIZE : (count - total_written);
            unsigned char *tmp = get_tls_chunk_buf(chunk, NULL);
            if (!tmp) { errno = ENOMEM; ret = -1; goto out; }

            memcpy(tmp, src + total_written, chunk);
            xor_encrypt_decrypt_fast(tmp, chunk);

            ssize_t n = real_pwrite(fd, tmp, chunk, off);
            if (n <= 0) { ret = (n == 0 ? total_written : n); goto out; }
            total_written += n;
            off += n;

            if ((total_written % (WRITE_BLOCK_SIZE * 16)) == 0 || (size_t)total_written == count) {
                double pct = (double)total_written * 100.0 / (double)count;
                DEBUG_LOG("pwrite进度: %zd / %zu (%.1f%%)", total_written, count, pct);
            }
        }
        ret = total_written;
        mark_fd_mmaps_modified(fd);
        { int t = 1; fd_ctx_update_flags(fd, &t, NULL); }

    out:
        ;
    }
    free(ctx.path);
    return ret;
}

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
                size_t total_bytes = size * nmemb;
                DEBUG_LOG("=====【fwrite Hook】文件=%s, 字节=%zu", ctx.path ? ctx.path : "未知", total_bytes);
                if (total_bytes <= 4096) log_hex_preview("fwrite加密前", (const unsigned char *)ptr, total_bytes);

                const unsigned char *src = (const unsigned char *)ptr;
                size_t total_written = 0;
                size_t elements_written = 0;

                while (total_written < total_bytes) {
                    size_t chunk = (total_bytes - total_written > WRITE_BLOCK_SIZE)
                                 ? WRITE_BLOCK_SIZE : (total_bytes - total_written);

                    unsigned char *tmp = get_tls_chunk_buf(chunk, NULL);
                    if (!tmp) { DEBUG_LOG("fwrite缓冲分配失败"); return 0; }

                    memcpy(tmp, src + total_written, chunk);
                    xor_encrypt_decrypt_fast(tmp, chunk);

                    size_t chunk_elems = chunk / size;
                    if (chunk_elems == 0 && chunk > 0) chunk_elems = 1;

                    size_t n = real_fwrite(tmp, size, chunk_elems, stream);
                    if (n == 0) { DEBUG_LOG("fwrite分块写入失败"); return elements_written; }

                    total_written += n * size;
                    elements_written += n;

                    if ((total_written % (WRITE_BLOCK_SIZE * 16)) == 0 || total_written == total_bytes) {
                        double pct = (double)total_written * 100.0 / (double)total_bytes;
                        DEBUG_LOG("fwrite进度: %zu / %zu (%.1f%%)", total_written, total_bytes, pct);
                    }
                }
                mark_fd_mmaps_modified(fd);
                { int t = 1; fd_ctx_update_flags(fd, &t, NULL); }
                free(ctx.path);
                return elements_written;
            }
            free(ctx.path);
        }
    }
    return real_fwrite(ptr, size, nmemb, stream);
}

// ==================== rename/renameat（常见保存流程） ====================

int rename(const char *oldpath, const char *newpath) {
    static int (*real_rename)(const char *, const char *) = NULL;
    if (!real_rename) {
        real_rename = dlsym(RTLD_NEXT, "rename");
        DEBUG_LOG("rename Hook已加载: real_rename=%p", real_rename);
    }
    if (oldpath && newpath) DEBUG_LOG("rename: '%s' -> '%s'", oldpath, newpath);
    int ret = real_rename(oldpath, newpath);
    if (ret != 0) DEBUG_LOG("rename失败: %s", strerror(errno));
    return ret;
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    static int (*real_renameat)(int, const char *, int, const char *) = NULL;
    if (!real_renameat) {
        real_renameat = dlsym(RTLD_NEXT, "renameat");
        DEBUG_LOG("renameat Hook已加载: real_renameat=%p", real_renameat);
    }
    if (oldpath && newpath) DEBUG_LOG("renameat: '%s' -> '%s'", oldpath, newpath);
    int ret = real_renameat(olddirfd, oldpath, newdirfd, newpath);
    if (ret != 0) DEBUG_LOG("renameat失败: %s", strerror(errno));
    return ret;
}

// ==================== 帮助函数：对某个区间做临时加密-同步-解密 ====================

static int encrypt_sync_decrypt(void *addr, size_t length, int restore_prot,
                                int (*sync_fn)(void *, size_t, int), int flags) {
    if (!addr || length == 0) return 0;
    // 加密
    if (safe_encrypt_memory_with_prot(addr, length, restore_prot) != 0) {
        DEBUG_LOG("encrypt_sync_decrypt: 加密失败 addr=%p len=%zu", addr, length);
        return -1;
    }
    // 同步
    int r = sync_fn(addr, length, flags);
    if (r != 0) {
        DEBUG_LOG("encrypt_sync_decrypt: 同步失败 %s", strerror(errno));
        // 尽力恢复为明文
        (void)safe_decrypt_memory_with_prot(addr, length, restore_prot);
        return r;
    }
    // 立即还原为明文
    if (safe_decrypt_memory_with_prot(addr, length, restore_prot) != 0) {
        DEBUG_LOG("encrypt_sync_decrypt: 解密恢复失败 addr=%p len=%zu", addr, length);
        return -1;
    }
    return 0;
}

// 遍历与 addr/length 有交集的目标映射，逐段执行临时加密-同步-解密
static int sync_overlapping_regions(void *addr, size_t length,
                                    int (*sync_fn)(void *, size_t, int), int flags) {
    int ret = 0;
    pthread_mutex_lock(&mmap_mutex);
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        mmap_region_t *rg = &mmap_regions[i];
        if (!rg->addr || !rg->should_decrypt) continue;
        char *a = (char *)addr;
        char *b = a + length;
        char *ra = (char *)rg->addr;
        char *rb = ra + rg->length;
        // 计算交集
        char *start = (a > ra) ? a : ra;
        char *end   = (b < rb) ? b : rb;
        if (end > start) {
            int restore_prot = rg->prot;
            void *sub_start = NULL; size_t sub_len = 0;
            align_to_pages(start, (size_t)(end - start), &sub_start, &sub_len);
            DEBUG_LOG("msync临时加密区间: rg=[%p,%p) sync=[%p,%p) 实际=[%p,%p) len=%zu",
                      ra, rb, a, b, sub_start, (char*)sub_start + sub_len, sub_len);
            pthread_mutex_unlock(&mmap_mutex);
            int r = encrypt_sync_decrypt(sub_start, sub_len, restore_prot, sync_fn, flags);
            pthread_mutex_lock(&mmap_mutex);
            if (r != 0) ret = r;
        }
    }
    pthread_mutex_unlock(&mmap_mutex);
    return ret;
}

// 针对某个 fd 的所有映射执行（用于 fsync/fdatasync）
static int sync_all_regions_of_fd(int fd, int (*sync_fn)(void *, size_t, int), int flags) {
    int ret = 0;
    pthread_mutex_lock(&mmap_mutex);
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        mmap_region_t *rg = &mmap_regions[i];
        if (!rg->addr || !rg->should_decrypt || rg->fd != fd) continue;
        int restore_prot = rg->prot;
        void *sub_start = NULL; size_t sub_len = 0;
        align_to_pages(rg->addr, rg->length, &sub_start, &sub_len);
        DEBUG_LOG("fsync/fdatasync临时加密区间: addr=%p len=%zu", sub_start, sub_len);
        pthread_mutex_unlock(&mmap_mutex);
        int r = encrypt_sync_decrypt(sub_start, sub_len, restore_prot, sync_fn, flags);
        pthread_mutex_lock(&mmap_mutex);
        if (r != 0) ret = r;
    }
    pthread_mutex_unlock(&mmap_mutex);
    return ret;
}

// ==================== mmap/msync/munmap Hook ====================

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    static void *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
    if (!real_mmap) {
        real_mmap = dlsym(RTLD_NEXT, "mmap");
        DEBUG_LOG("mmap Hook已加载: real_mmap=%p", real_mmap);
    }

    void *ret = real_mmap(addr, length, prot, flags, fd, offset);
    if (ret == MAP_FAILED) return ret;

    int should_decrypt = 0;
    if (fd >= 0) {
        fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
        if (fd_ctx_get_copy(fd, &ctx)) {
            should_decrypt = ctx.is_target;
            free(ctx.path);
        } else {
            char *path = dup_path_from_fd(fd);
            if (path) { should_decrypt = is_dwg_path(path); free(path); }
        }
    }

    track_mmap_region(ret, length, should_decrypt, prot, flags, fd, offset);

    if (should_decrypt) {
        DEBUG_LOG("mmap成功，开始流式解密映射: addr=%p, len=%zu, prot=0x%x, flags=0x%x", ret, length, prot, flags);
        // 只对 MAP_SHARED / MAP_PRIVATE 都解密，因为进程内需要明文。
        (void)safe_decrypt_memory_with_prot(ret, length, prot);
    }
    return ret;
}

int msync(void *addr, size_t length, int flags) {
    static int (*real_msync)(void *, size_t, int) = NULL;
    if (!real_msync) {
        real_msync = dlsym(RTLD_NEXT, "msync");
        DEBUG_LOG("msync Hook已加载: real_msync=%p", real_msync);
    }

    // 如果该区间涉及到我们解密过的 MAP_SHARED 映射，则对交集区间做“临时加密→同步→解密”
    int handled = sync_overlapping_regions(addr, length, real_msync, flags);
    if (handled == 0) {
        // 同步成功（或没有目标映射需要处理），但仍需调用一次真实 msync 以覆盖非目标映射、或无交集时的默认行为。
        // 注意：若有交集，我们已在同步时对相应区间调用过 real_msync；此处再次调用对整个区间一般无害，
        // 但为避免重复成本，仅当没有任何目标交集（handled==0 且真实返回值仍需产生）时再调一次。
        // 这里采用最保守实现：仍调用一次，内核会快速返回。
        return real_msync(addr, length, flags);
    }
    // 若 sync_overlapping_regions 返回非 0，说明我们在包裹过程中遇到错误；为了不隐藏问题，仍返回错误码。
    return handled;
}

int munmap(void *addr, size_t length) {
    static int (*real_munmap)(void *, size_t) = NULL;
    if (!real_munmap) {
        real_munmap = dlsym(RTLD_NEXT, "munmap");
        DEBUG_LOG("munmap Hook已加载: real_munmap=%p", real_munmap);
    }

    int need_encrypt = 0;
    int restore_prot = PROT_READ | PROT_WRITE;
    pthread_mutex_lock(&mmap_mutex);
    mmap_region_t *region = find_mmap_region_containing(addr);
    if (region && region->should_decrypt) {
        need_encrypt = 1;
        restore_prot = region->prot;
    }
    pthread_mutex_unlock(&mmap_mutex);

    if (need_encrypt) {
        DEBUG_LOG("munmap前临时加密并刷盘: addr=%p, len=%zu", addr, length);
        // 先加密并 msync(MS_SYNC)，再解密恢复，然后再真正 munmap。
        void *sub_start = NULL; size_t sub_len = 0;
        align_to_pages(addr, length, &sub_start, &sub_len);

        // 加密→msync→解密
        if (encrypt_sync_decrypt(sub_start, sub_len, restore_prot, msync, MS_SYNC) != 0) {
            DEBUG_LOG("munmap: 加密刷盘失败，仍尝试继续解除映射");
        }
    }

    int ret = real_munmap(addr, length);
    if (ret == 0) {
        DEBUG_LOG("munmap成功: addr=%p, len=%zu", addr, length);
        untrack_mmap_region(addr, length);
    } else {
        DEBUG_LOG("munmap失败: %s", strerror(errno));
    }
    return ret;
}

// ==================== fsync/fdatasync Hook（对同 fd 的映射做临时加密-同步-解密） ====================

int fsync(int fd) {
    static int (*real_fsync)(int) = NULL;
    static int (*real_msync)(void *, size_t, int) = NULL;
    if (!real_fsync) {
        real_fsync = dlsym(RTLD_NEXT, "fsync");
        DEBUG_LOG("fsync Hook已加载: real_fsync=%p", real_fsync);
    }
    if (!real_msync) {
        real_msync = dlsym(RTLD_NEXT, "msync");
    }

    fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    if (fd_ctx_get_copy(fd, &ctx)) {
        if (ctx.is_target) {
            DEBUG_LOG("fsync 目标DWG：fd=%d, 文件=%s（对所有相关映射执行临时加密同步）", fd, ctx.path ? ctx.path : "未知");
            // 对该 fd 的所有映射做临时加密-同步-解密，以防落盘为明文
            (void)sync_all_regions_of_fd(fd, real_msync, MS_SYNC);
        }
        free(ctx.path);
    }
    int ret = real_fsync(fd);
    if (ret != 0) DEBUG_LOG("fsync失败: %s", strerror(errno));
    return ret;
}

int fdatasync(int fd) {
    static int (*real_fdatasync)(int) = NULL;
    static int (*real_msync)(void *, size_t, int) = NULL;
    if (!real_fdatasync) {
        real_fdatasync = dlsym(RTLD_NEXT, "fdatasync");
        DEBUG_LOG("fdatasync Hook已加载: real_fdatasync=%p", real_fdatasync);
    }
    if (!real_msync) {
        real_msync = dlsym(RTLD_NEXT, "msync");
    }

    fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    if (fd_ctx_get_copy(fd, &ctx)) {
        if (ctx.is_target) {
            DEBUG_LOG("fdatasync 目标DWG：fd=%d, 文件=%s（对所有相关映射执行临时加密同步）", fd, ctx.path ? ctx.path : "未知");
            (void)sync_all_regions_of_fd(fd, real_msync, MS_SYNC);
        }
        free(ctx.path);
    }
    int ret = real_fdatasync(fd);
    if (ret != 0) DEBUG_LOG("fdatasync失败: %s", strerror(errno));
    return ret;
}

// ==================== 初始化与收尾 ====================

__attribute__((constructor))
static void init_hook(void) {
    DEBUG_LOG("==== DWG Hook 初始化 ====");
}

__attribute__((destructor))
static void fini_hook(void) {
    DEBUG_LOG("==== DWG Hook 结束 ====");
}
 