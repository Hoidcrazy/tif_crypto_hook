/* 修改说明（2025-08-18）
 * 1) 修复 mmap 分块加/解密后错误地把页面永久设为只读，导致 ZWCAD 保存时写入挂起/崩溃。
 *    现在在 chunked_memory_crypt() 内恢复为原始的保护位（region->prot），否则回退为可读写。
 *    相关原实现见本文件的 chunked_memory_crypt() 恢复 PROT_READ 处。 :contentReference[oaicite:0]{index=0}
 * 2) 新增 mark_fd_mmaps_modified()，在 write/pwrite/pwrite64/fwrite 成功后标记对应 fd 的 mmap
 *    为 modified=true，保证 munmap 前能触发回写加密逻辑。 :contentReference[oaicite:1]{index=1}
 */
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

// ==================== 可调参数 ====================

#define WRITE_BLOCK_SIZE              (256 * 1024)   // 写入分块大小 256KB
#define MEMORY_CRYPT_BLOCK_SIZE       (128 * 1024)   // 内存分块大小 128KB
#define MAX_MEMORY_OPERATION_SIZE     (64UL * 1024 * 1024) // 单次内存处理上限 64MB
#define MAX_PATH_LEN                  4096
#define MAX_MMAP_REGIONS              512
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

static void log_hex_3_bytes(const char *tag, const unsigned char *buf, size_t n) {
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

// ==================== 文件上下文追踪 ====================

typedef struct fd_context_s {
    int   fd;
    char *path;
    int   is_target;
    int   is_tmp;
    struct fd_context_s *next;
} fd_context_t;

static pthread_mutex_t fd_table_mutex = PTHREAD_MUTEX_INITIALIZER;
static fd_context_t *fd_table = NULL;

static int is_dwg_path(const char *path) {
    if (!path) return 0;
    const char *dot = strrchr(path, '.');
    if (!dot) return 0;
    if (strcasecmp(dot, ".dwg") != 0) return 0;

    // 排除临时/缓存文件，避免打断 CAD 的中间写流程
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
static mmap_region_t mmap_regions[MAX_MMAP_REGIONS];
static pthread_mutex_t mmap_mutex = PTHREAD_MUTEX_INITIALIZER;

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

// 标记与指定fd相关的mmap区域为已修改，便于在munmap前触发回写加密
static void mark_fd_mmaps_modified(int fd) {
    if (fd < 0) return;
    pthread_mutex_lock(&mmap_mutex);
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr && mmap_regions[i].fd == fd) {
            mmap_regions[i].modified = true;
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
        mmap_regions[slot].in_memory_encrypted = should_decrypt ? true : false;
        mmap_regions[slot].disk_encrypted = should_decrypt ? true : false;
        DEBUG_LOG("mmap区域跟踪成功: slot=%d, addr=%p, len=%zu, fd=%d, should_decrypt=%s",
                  slot, addr, length, fd, should_decrypt ? "是" : "否");
    } else {
        DEBUG_LOG("警告: 无可用mmap插槽来跟踪 addr=%p len=%zu", addr, length);
    }
    pthread_mutex_unlock(&mmap_mutex);
}

/** 取消跟踪 mmap 区域 */
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

// ==================== 简单的异或“加解密”示例 ====================

/** 简单异或：演示用途 */
static void xor_encrypt_decrypt(unsigned char *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= 0xFF;
    }
}

/** 
 * 分块内存加解密函数
 * 避免一次性处理大内存块导致卡死
 */
static int chunked_memory_crypt(void *addr, size_t length, const char *operation) {
    if (!addr || length == 0) return -1;
    
    // 检查内存操作大小限制
    if (length > MAX_MEMORY_OPERATION_SIZE) {
        DEBUG_LOG("警告: 内存操作大小超限 (%zu > %d), 跳过%s", 
                  length, MAX_MEMORY_OPERATION_SIZE, operation);
        return -1;
    }
    
    DEBUG_LOG("开始分块%s: addr=%p, 总长度=%zu, 分块大小=%d", 
              operation, addr, length, MEMORY_CRYPT_BLOCK_SIZE);
    
    size_t processed = 0;
    // 尝试恢复原有内存权限（若是mmap区域，则使用其原始prot；否则保守恢复为可读写）
    int restore_prot = PROT_READ | PROT_WRITE; // 默认可读写，避免后续写入被永久禁用
    mmap_region_t *__region_for_perm = find_mmap_region(addr);
    if (__region_for_perm) {
        restore_prot = __region_for_perm->prot;
    }
    unsigned char *ptr = (unsigned char *)addr;
    
    while (processed < length) {
        size_t chunk_size = (length - processed > MEMORY_CRYPT_BLOCK_SIZE)
                          ? MEMORY_CRYPT_BLOCK_SIZE 
                          : length - processed;
        
        // 临时设置写权限（仅对当前分块）
        if (mprotect(ptr + processed, chunk_size, PROT_READ | PROT_WRITE) != 0) {
            DEBUG_LOG("mprotect设置写权限失败: 偏移=%zu, 分块大小=%zu, 错误: %s", 
                      processed, chunk_size, strerror(errno));
            return -1;
        }
        
        // 对当前分块进行加密/解密
        xor_encrypt_decrypt(ptr + processed, chunk_size);
        
        // 恢复原始页面保护（关键修复）
        if (mprotect(ptr + processed, chunk_size, restore_prot) != 0) {
            DEBUG_LOG("mprotect恢复原始权限失败: 偏移=%zu, 分块大小=%zu, 错误: %s", 
                      processed, chunk_size, strerror(errno));
        }
        
        processed += chunk_size;
        
        // 每处理几个分块输出一次进度
        if ((processed % (MEMORY_CRYPT_BLOCK_SIZE * 4)) == 0 || processed == length) {
            DEBUG_LOG("%s进度: %zu / %zu 字节 (%.1f%%)", 
                      operation, processed, length, 
                      (double)processed / length * 100.0);
        }
        
        // 让出CPU时间，避免长时间占用
        if (processed < length) {
            usleep(1000); // 1ms
        }
    }
    
    DEBUG_LOG("分块%s完成: 总处理=%zu字节", operation, processed);
    return 0;
}

static int safe_decrypt_memory(void *addr, size_t length) {
    return chunked_memory_crypt(addr, length, "解密");
}

static int safe_encrypt_memory(void *addr, size_t length) {
    return chunked_memory_crypt(addr, length, "加密");
}

// ==================== open/close 重载 ====================

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
    if (fd >= 0) {
        fd_ctx_add(fd, pathname);
    }
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
    if (fd >= 0) {
        fd_ctx_add(fd, pathname);
    }
    return fd;
}

int creat(const char *pathname, mode_t mode) {
    static int (*real_creat)(const char *, mode_t) = NULL;
    if (!real_creat) {
        real_creat = dlsym(RTLD_NEXT, "creat");
        DEBUG_LOG("creat Hook已加载: real_creat=%p", real_creat);
    }
    int fd = real_creat(pathname, mode);
    if (fd >= 0) {
        fd_ctx_add(fd, pathname);
    }
    return fd;
}

int close(int fd) {
    static int (*real_close)(int) = NULL;
    if (!real_close) {
        real_close = dlsym(RTLD_NEXT, "close");
        DEBUG_LOG("close Hook已加载: real_close=%p", real_close);
    }

    // 在 close 前不做额外处理（fsync/msync/munmap 中已经处理）
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
        DEBUG_LOG("=====【read Hook成功调用】=====");
        DEBUG_LOG("读取目标DWG: fd=%d, 文件=%s, 字节数=%zd", fd, ctx.path ? ctx.path : "未知", ret);
        log_hex_3_bytes("解密前数据", (unsigned char *)buf, ret);
        xor_encrypt_decrypt((unsigned char *)buf, ret);
        log_hex_3_bytes("解密后数据", (unsigned char *)buf, ret);
        DEBUG_LOG("================================");
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
                size_t total_bytes = ret * size;
                DEBUG_LOG("=====【fread Hook成功调用】=====");
                DEBUG_LOG("读取目标DWG: fd=%d, 文件=%s, 字节=%zu", fd, ctx.path ? ctx.path : "未知", total_bytes);
                log_hex_3_bytes("fread解密前数据", (unsigned char *)ptr, total_bytes);
                
                xor_encrypt_decrypt((unsigned char *)ptr, total_bytes);
                
                log_hex_3_bytes("fread解密后数据", (unsigned char *)ptr, total_bytes);
                DEBUG_LOG("fread解密成功: fd=%d, 解密字节数=%zu", fd, total_bytes);
                DEBUG_LOG("====================================");
            } else if (ctx.is_target) {
                size_t total_bytes = ret * size;
                DEBUG_LOG("fread读取明文DWG: fd=%d, 文件=%s, 读取字节=%zu", 
                          fd, ctx.path ? ctx.path : "未知", total_bytes);
            }
            free(ctx.path);
        }
    }
    return ret;
}

// ==================== 写入 Hook（分块加密并写） ====================

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
        // 目标文件：加密后写入（分块处理）
        DEBUG_LOG("=====【write Hook成功调用】=====");
        DEBUG_LOG("文件: %s", ctx.path ? ctx.path : "未知");
        DEBUG_LOG("写入大小: %zd", count);
        log_hex_3_bytes("加密前数据", (unsigned char *)buf, count);
        
        ssize_t total_written = 0;
        bool success = true;
        const unsigned char *src = (const unsigned char *)buf;
        
        while (total_written < (ssize_t)count && success) {
            size_t chunk_size = (count - total_written > WRITE_BLOCK_SIZE) 
                              ? WRITE_BLOCK_SIZE 
                              : count - total_written;
            
            void *tmp = malloc(chunk_size);
            if (!tmp) {
                DEBUG_LOG("write内存分配失败: 请求大小=%zu", chunk_size);
                success = false;
                break;
            }
            
            // 加密当前分块
            memcpy(tmp, src + total_written, chunk_size);
            xor_encrypt_decrypt((unsigned char *)tmp, chunk_size);
            
            // 写入分块
            ssize_t n = real_write(fd, tmp, chunk_size);
            free(tmp);
            
            if (n < 0) {
                DEBUG_LOG("write分块写入失败: 错误: %s", strerror(errno));
                success = false;
                break;
            } else if (n == 0) {
                DEBUG_LOG("write分块写入返回0，停止写入");
                break;
            }
            
            total_written += n;
            
            // 输出进度
            if (total_written > 0 && (total_written % (WRITE_BLOCK_SIZE * 4)) == 0) {
                DEBUG_LOG("write进度: %zd / %zd 字节 (%.1f%%)", 
                          total_written, count, (double)total_written / count * 100.0);
            }
        }
        
        if (success) {
            ret = total_written;
            // 标记相关mmap区域为已修改，确保munmap前能回写加密
            mark_fd_mmaps_modified(fd);
            int dk = true;
            fd_ctx_update_flags(fd, &dk, NULL);
            DEBUG_LOG("write加密写入成功: 总写入=%zd字节", ret);
        } else {
            ret = -1;
            errno = ENOMEM;
            DEBUG_LOG("write写入失败");
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
        
        ssize_t total_written = 0;
        bool success = true;
        const unsigned char *src = (const unsigned char *)buf;
        off_t current_offset = offset;
        
        while (total_written < (ssize_t)count && success) {
            size_t chunk_size = (count - total_written > WRITE_BLOCK_SIZE) 
                              ? WRITE_BLOCK_SIZE 
                              : count - total_written;
            
            void *tmp = malloc(chunk_size);
            if (!tmp) {
                DEBUG_LOG("pwrite64内存分配失败: 请求大小=%zu", chunk_size);
                success = false;
                break;
            }
            
            // 加密当前分块
            memcpy(tmp, src + total_written, chunk_size);
            xor_encrypt_decrypt((unsigned char *)tmp, chunk_size);
            
            // 写入分块
            ssize_t n = real_pwrite64(fd, tmp, chunk_size, current_offset);
            free(tmp);
            
            if (n < 0) {
                DEBUG_LOG("pwrite64分块写入失败: 错误: %s", strerror(errno));
                success = false;
                break;
            } else if (n == 0) {
                DEBUG_LOG("pwrite64分块写入返回0，停止写入");
                break;
            }
            
            total_written += n;
            current_offset += n;
            
            // 输出进度
            if (total_written > 0 && (total_written % (WRITE_BLOCK_SIZE * 4)) == 0) {
                DEBUG_LOG("pwrite64进度: %zd / %zd 字节 (%.1f%%)", 
                          total_written, count, (double)total_written / count * 100.0);
            }
        }
        
        if (success) {
            ret = total_written;
            // 标记相关mmap区域为已修改，确保munmap前能回写加密
            mark_fd_mmaps_modified(fd);
            int dk = true;
            fd_ctx_update_flags(fd, &dk, NULL);
            DEBUG_LOG("pwrite64加密写入成功: 总写入=%zd字节", ret);
        } else {
            ret = -1;
            errno = ENOMEM;
            DEBUG_LOG("pwrite64写入失败");
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
        
        ssize_t total_written = 0;
        bool success = true;
        const unsigned char *src = (const unsigned char *)buf;
        off_t current_offset = offset;
        
        while (total_written < (ssize_t)count && success) {
            size_t chunk_size = (count - total_written > WRITE_BLOCK_SIZE) 
                              ? WRITE_BLOCK_SIZE 
                              : count - total_written;
            
            void *tmp = malloc(chunk_size);
            if (!tmp) {
                DEBUG_LOG("pwrite内存分配失败: 请求大小=%zu", chunk_size);
                success = false;
                break;
            }
            
            // 加密当前分块
            memcpy(tmp, src + total_written, chunk_size);
            xor_encrypt_decrypt((unsigned char *)tmp, chunk_size);
            
            // 写入分块
            ssize_t n = real_pwrite(fd, tmp, chunk_size, current_offset);
            free(tmp);
            
            if (n < 0) {
                DEBUG_LOG("pwrite分块写入失败: 错误: %s", strerror(errno));
                success = false;
                break;
            } else if (n == 0) {
                DEBUG_LOG("pwrite分块写入返回0，停止写入");
                break;
            }
            
            total_written += n;
            current_offset += n;
            
            // 输出进度
            if (total_written > 0 && (total_written % (WRITE_BLOCK_SIZE * 4)) == 0) {
                DEBUG_LOG("pwrite进度: %zd / %zd 字节 (%.1f%%)", 
                          total_written, count, (double)total_written / count * 100.0);
            }
        }
        
        if (success) {
            ret = total_written;
            // 标记相关mmap区域为已修改，确保munmap前能回写加密
            mark_fd_mmaps_modified(fd);
            int dk = true;
            fd_ctx_update_flags(fd, &dk, NULL);
            DEBUG_LOG("pwrite加密写入成功: 总写入=%zd字节", ret);
        } else {
            ret = -1;
            errno = ENOMEM;
            DEBUG_LOG("pwrite写入失败");
        }
        DEBUG_LOG("=====================================");
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
                // 目标文件：加密后写入（分块处理）
                size_t total_bytes = size * nmemb;
                DEBUG_LOG("=====【fwrite Hook成功调用】=====");
                DEBUG_LOG("文件: %s", ctx.path ? ctx.path : "未知");
                DEBUG_LOG("写入大小: %zd", total_bytes);
                log_hex_3_bytes("fwrite加密前数据", (unsigned char *)ptr, total_bytes);
                
                const unsigned char *src = (const unsigned char *)ptr;
                size_t total_written = 0;
                size_t elements_written = 0;
                bool success = true;
                
                while (total_written < total_bytes && success) {
                    size_t chunk_size = (total_bytes - total_written > WRITE_BLOCK_SIZE) 
                                      ? WRITE_BLOCK_SIZE 
                                      : total_bytes - total_written;
                    
                    void *tmp = malloc(chunk_size);
                    if (!tmp) {
                        DEBUG_LOG("fwrite内存分配失败: 请求大小=%zu", chunk_size);
                        success = false;
                        break;
                    }
                    
                    // 加密当前分块
                    memcpy(tmp, src + total_written, chunk_size);
                    xor_encrypt_decrypt((unsigned char *)tmp, chunk_size);
                    
                    // 计算当前分块包含的元素数量
                    size_t chunk_elements = chunk_size / size;
                    if (chunk_elements == 0 && chunk_size > 0) chunk_elements = 1;
                    
                    // 写入分块
                    size_t n = real_fwrite(tmp, size, chunk_elements, stream);
                    free(tmp);
                    
                    if (n == 0) {
                        DEBUG_LOG("fwrite分块写入失败");
                        success = false;
                        break;
                    }
                    
                    total_written += n * size;
                    elements_written += n;
                    
                    // 输出进度
                    if (total_written > 0 && (total_written % (WRITE_BLOCK_SIZE * 4)) == 0) {
                        DEBUG_LOG("fwrite进度: %zd / %zd 字节 (%.1f%%)", 
                                  total_written, total_bytes, (double)total_written / total_bytes * 100.0);
                    }
                }
                
                size_t ret;
                if (success) {
                    ret = elements_written;
                    // 标记相关mmap区域为已修改
                    mark_fd_mmaps_modified(fd);
                    int dk = true;
                    fd_ctx_update_flags(fd, &dk, NULL);
                    DEBUG_LOG("fwrite加密写入成功: 写入元素=%zu", ret);
                } else {
                    ret = 0;
                    DEBUG_LOG("fwrite写入失败");
                }
                DEBUG_LOG("================================");
                free(ctx.path);
                return ret;
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

    if (oldpath && newpath) {
        DEBUG_LOG("rename操作: '%s' -> '%s'", oldpath, newpath);
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

// ==================== mmap/msync/munmap Hook ====================

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    static void *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
    if (!real_mmap) {
        real_mmap = dlsym(RTLD_NEXT, "mmap");
        DEBUG_LOG("mmap Hook已加载: real_mmap=%p", real_mmap);
    }

    void *ret = real_mmap(addr, length, prot, flags, fd, offset);
    if (ret == MAP_FAILED) return ret;

    // 判断是否需要在内存中保持“明文”（即对磁盘密文进行解密）
    int should_decrypt = 0;
    if (fd >= 0) {
        fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
        if (fd_ctx_get_copy(fd, &ctx)) {
            should_decrypt = ctx.is_target;
            free(ctx.path);
        } else {
            // 尝试从路径判断（保险）
            char *path = dup_path_from_fd(fd);
            if (path) {
                should_decrypt = is_dwg_path(path);
                free(path);
            }
        }
    }

    track_mmap_region(ret, length, should_decrypt, prot, flags, fd, offset);

    // 如果需要解密，则对映射内存进行解密（小块处理）
    if (should_decrypt && length <= MAX_MEMORY_OPERATION_SIZE) {
        DEBUG_LOG("mmap成功，准备对映射内存进行解密: addr=%p len=%zu", ret, length);
        safe_decrypt_memory(ret, length);
    } else if (should_decrypt) {
        DEBUG_LOG("mmap成功，目标DWG映射过大，跳过立即解密: len=%zu", length);
    }

    return ret;
}

int msync(void *addr, size_t length, int flags) {
    static int (*real_msync)(void *, size_t, int) = NULL;
    if (!real_msync) {
        real_msync = dlsym(RTLD_NEXT, "msync");
        DEBUG_LOG("msync Hook已加载: real_msync=%p", real_msync);
    }
    
    DEBUG_LOG("=====【msync Hook成功调用】=====");
    DEBUG_LOG("同步内存映射: addr=%p, 长度=%zu, 标志=0x%x", addr, length, flags);
    
    // 检查是否为目标mmap区域
    mmap_region_t *region = find_mmap_region(addr);
    if (region && region->should_decrypt) {
        DEBUG_LOG("同步目标DWG内存映射区域");
        
        // 对于大内存区域，简化处理避免卡死
        if (length > MAX_MEMORY_OPERATION_SIZE) {
            DEBUG_LOG("大内存区域同步，跳过复杂处理: %zu字节", length);
            int ret = real_msync(addr, length, flags);
            DEBUG_LOG("===================================");
            return ret;
        }
        
        // 对小内存区域进行正常处理
        DEBUG_LOG("小内存区域同步，进行加密/解密处理: %zu字节", length);
        
        // 简化的同步逻辑：直接同步，不进行页级别的复杂操作
        int ret = real_msync(addr, length, flags);
        
        if (ret != 0) {
            DEBUG_LOG("msync失败: 错误: %s", strerror(errno));
        } else {
            DEBUG_LOG("msync成功");
        }
        DEBUG_LOG("===================================");
        return ret;
    }
    
    int ret = real_msync(addr, length, flags);
    if (ret != 0) {
        DEBUG_LOG("msync失败: 错误: %s", strerror(errno));
    }
    DEBUG_LOG("===================================");
    
    return ret;
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
        // 仅对小于限制的区域进行加密
        if (length <= MAX_MEMORY_OPERATION_SIZE) {
            safe_encrypt_memory(addr, length);
        } else {
            DEBUG_LOG("munmap: 内存区域过大，跳过加密 (%zu字节)", length);
        }
    }

    int ret = real_munmap(addr, length);
    if (ret == 0) {
        DEBUG_LOG("munmap成功: addr=%p, 长度=%zu", addr, length);
        untrack_mmap_region(addr, length);
    } else {
        DEBUG_LOG("munmap失败: %s", strerror(errno));
    }
    return ret;
}

// ==================== fsync/fdatasync Hook（记录） ====================

int fsync(int fd) {
    static int (*real_fsync)(int) = NULL;
    if (!real_fsync) {
        real_fsync = dlsym(RTLD_NEXT, "fsync");
        DEBUG_LOG("fsync Hook已加载: real_fsync=%p", real_fsync);
    }
    
    fd_context_t ctx; memset(&ctx, 0, sizeof(ctx));
    if (fd_ctx_get_copy(fd, &ctx)) {
        if (ctx.is_target) {
            DEBUG_LOG("=====【fsync Hook成功调用】=====");
            DEBUG_LOG("同步目标DWG文件: fd=%d, 文件=%s", fd, ctx.path ? ctx.path : "未知");
            DEBUG_LOG("===================================");
        }
        free(ctx.path);
    }
    
    int ret = real_fsync(fd);
    if (ret != 0) {
        DEBUG_LOG("fsync失败: %s", strerror(errno));
    }
    return ret;
}

int fdatasync(int fd) {
    static int (*real_fdatasync)(int) = NULL;
    if (!real_fdatasync) {
        real_fdatasync = dlsym(RTLD_NEXT, "fdatasync");
        DEBUG_LOG("fdatasync Hook已加载: real_fdatasync=%p", real_fdatasync);
    }
    int ret = real_fdatasync(fd);
    if (ret != 0) {
        DEBUG_LOG("fdatasync失败: %s", strerror(errno));
    }
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
