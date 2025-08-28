/*
 * dwg_hook_improved.c
 * 
 * 编译命令：
 *   gcc -shared -fPIC -o libdwg_hook.so dwg_hook_improved.c -ldl -lpthread
 * 
 * 使用方法：
 *   export DWG_HOOK_DEBUG=1  # 可选：启用调试日志
 *   LD_PRELOAD=/home/chane/tif_crypto_hook/libdwg_hook.so /opt/apps/zwcad2026/ZWCADRUN.sh
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <limits.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sched.h>
#include <time.h>

// ==================== 配置参数 ====================
#define ENABLE_INLINE_ENCRYPTION      1                    // 0:禁用/1:启用 - 在线加密（方案2）
#define ENABLE_FINAL_FILE_ENCRYPTION  1                    // 0:禁用/1:启用 - 整文件替换加密（方案1）
#define WRITE_BLOCK_SIZE              (512 * 1024)         // 写入分块大小：512KB
#define MMAP_CRYPT_BLOCK              (2UL * 1024 * 1024)  // 内存加解密分块：2MB
#define MAX_PATH_LEN                  4096
#define MAX_MMAP_REGIONS              4096                 // 最大映射区域数量
#define LOG_HEX_PREVIEW_BYTES         48                   // 日志中显示的十六进制字节数

// ==================== 内部IO护栏（防止重入） ====================
static __thread int tls_internal_io = 0;  // 0=外部调用; >0=库内自发调用

#define BEGIN_INTERNAL_IO()  do { tls_internal_io++; } while (0)
#define END_INTERNAL_IO()    do { tls_internal_io--; } while (0)

static inline int is_internal_io(void) { 
    return tls_internal_io > 0; 
}

// ==================== 调试日志系统 ====================
static int g_debug_enabled = -1;

static int is_debug_enabled(void) {
    if (g_debug_enabled == -1) {
        const char *env = getenv("DWG_HOOK_DEBUG");
        g_debug_enabled = (env && *env && strcmp(env, "0") != 0) ? 1 : 0;
    }
    return g_debug_enabled;
}

static void debug_log(const char *fmt, ...) {
    if (!is_debug_enabled()) return;
    static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&log_mutex);
    
    // 添加时间戳
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", tm_info);
    
    FILE *fp = fopen("/tmp/dwg_hook.log", "a");
    if (fp) {
        fprintf(fp, "[%s] ", timestamp);
        va_list ap;
        va_start(ap, fmt);
        vfprintf(fp, fmt, ap);
        va_end(ap);
        fprintf(fp, "\n");
        fclose(fp);
    }
    pthread_mutex_unlock(&log_mutex);
}

#define DEBUG_LOG(...) do { debug_log(__VA_ARGS__); } while(0)

static void log_hex_preview(const char *tag, const unsigned char *buf, size_t n) {
    if (!is_debug_enabled() || !buf || n == 0) return;
    size_t show = n < LOG_HEX_PREVIEW_BYTES ? n : LOG_HEX_PREVIEW_BYTES;
    char line[LOG_HEX_PREVIEW_BYTES * 3 + 128];
    int offset = snprintf(line, sizeof(line), "%s (%zu字节): ", tag, n);
    for (size_t i = 0; i < show && offset + 4 < (int)sizeof(line); ++i) {
        offset += snprintf(line + offset, sizeof(line) - offset, "%02X ", buf[i]);
    }
    if (n > show) {
        snprintf(line + offset, sizeof(line) - offset, "...");
    }
    DEBUG_LOG("%s", line);
}

// ==================== 页对齐工具函数 ====================
static inline size_t get_page_size(void) {
    static size_t page_size = 0;
    if (!page_size) {
        page_size = sysconf(_SC_PAGESIZE);
        if (page_size == 0) page_size = 4096; // 默认4KB页
    }
    return page_size;
}

static inline void align_to_pages(void *addr, size_t len, void **out_start, size_t *out_len) {
    size_t ps = get_page_size();
    uintptr_t start_ptr = (uintptr_t)addr;
    uintptr_t aligned_start = start_ptr & ~(ps - 1);  // 向下对齐到页边界
    uintptr_t end_ptr = start_ptr + len;
    uintptr_t aligned_end = (end_ptr + ps - 1) & ~(ps - 1);  // 向上对齐到页边界
    *out_start = (void*)aligned_start;
    *out_len = (size_t)(aligned_end - aligned_start);
}

// ==================== 文件描述符上下文管理 ====================
typedef struct fd_context_s {
    int fd;
    char *path;
    int is_target_dwg;              // 是否为目标DWG文件
    int is_temp_file;               // 是否为临时文件
    int should_encrypt_on_write;    // 是否应在写入时加密（方案2核心标记）
    int saw_plain_writes;           // 是否见过明文写入
    struct fd_context_s *next;
} fd_context_t;

static pthread_mutex_t fd_table_mutex = PTHREAD_MUTEX_INITIALIZER;
static fd_context_t *fd_table = NULL;

// 判断是否为目标DWG文件（排除临时文件和备份文件）
static int is_target_dwg_file(const char *path) {
    if (!path) return 0;
    
    // 检查扩展名
    const char *ext = strrchr(path, '.');
    if (!ext || strcasecmp(ext, ".dwg") != 0) return 0;
    
    // 排除临时文件、备份文件等
    if (strstr(path, ".tmp") || strstr(path, ".TMP") || 
        strstr(path, "~") || strstr(path, ".bak") || 
        strstr(path, ".sv$") || strstr(path, "autosave") ||
        strstr(path, "temp") || strstr(path, "TEMP") ||
        strstr(path, "zwTm") || strstr(path, "zwsave")) {  // 添加CAD特有的临时文件模式
        return 0;
    }
    
    return 1;
}

// 【方案2新增】判断是否为临时文件（需要写入时加密）
static int is_temporary_file(const char *path) {
    if (!path) return 0;
    
    // 检测各种临时文件模式
    if (strstr(path, ".tmp") || strstr(path, ".TMP") || 
        strstr(path, "temp") || strstr(path, "TEMP") ||
        strstr(path, "zwTm") || strstr(path, "zwsave") ||
        strstr(path, "autosave") || strstr(path, "~")) {
        return 1;
    }
    
    return 0;
}

static void fd_context_add(int fd, const char *path) {
    if (fd < 0) return;
    
    pthread_mutex_lock(&fd_table_mutex);
    fd_context_t *node = calloc(1, sizeof(fd_context_t));
    if (!node) {
        pthread_mutex_unlock(&fd_table_mutex);
        return;
    }
    
    node->fd = fd;
    if (path) node->path = strdup(path);
    node->is_target_dwg = is_target_dwg_file(path);
    
    // 检测临时文件
    node->is_temp_file = (!node->is_target_dwg && path && 
                         (strstr(path, ".tmp") || strstr(path, "temp") || strstr(path, "~") ||
                           strstr(path, "zwTm") || strstr(path, "zwsave") || strstr(path, ".bak")));
    
    // 【方案2】临时文件和目标DWG文件都需要加密写入（防止明文落盘）
    node->should_encrypt_on_write = ENABLE_INLINE_ENCRYPTION && (node->is_target_dwg || node->is_temp_file);
    
    
    node->next = fd_table;
    fd_table = node;
    
    if (node->is_target_dwg || node->is_temp_file) {
        DEBUG_LOG("添加文件上下文: fd=%d, 路径=%s, 目标DWG=%s, 临时文件=%s, 需要加密写入=%s", 
                 fd, path ? path : "(空)", 
                 node->is_target_dwg ? "是" : "否",
                 node->is_temp_file ? "是" : "否",
                 node->should_encrypt_on_write ? "是" : "否");
    }
    
    pthread_mutex_unlock(&fd_table_mutex);
}

static void fd_context_remove(int fd) {
    pthread_mutex_lock(&fd_table_mutex);
    fd_context_t **pp = &fd_table;
    while (*pp) {
        if ((*pp)->fd == fd) {
            fd_context_t *to_remove = *pp;
            *pp = (*pp)->next;
            
            if (to_remove->is_target_dwg) {
                DEBUG_LOG("移除目标DWG文件上下文: fd=%d, 路径=%s", 
                         fd, to_remove->path ? to_remove->path : "(空)");
            } else if (to_remove->is_temp_file) {
                DEBUG_LOG("移除临时文件上下文: fd=%d, 路径=%s", 
                         fd, to_remove->path ? to_remove->path : "(空)");
            }
            
            if (to_remove->path) free(to_remove->path);
            free(to_remove);
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&fd_table_mutex);
}

static int fd_context_get_info(int fd, fd_context_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    
    pthread_mutex_lock(&fd_table_mutex);
    fd_context_t *current = fd_table;
    while (current) {
        if (current->fd == fd) {
            out->fd = current->fd;
            out->is_target_dwg = current->is_target_dwg;
            out->is_temp_file = current->is_temp_file;
            out->should_encrypt_on_write = current->should_encrypt_on_write;
            if (current->path) out->path = strdup(current->path);
            pthread_mutex_unlock(&fd_table_mutex);
            return 1;
        }
        current = current->next;
    }
    pthread_mutex_unlock(&fd_table_mutex);
    return 0;
}

// 【方案2新增】根据路径标记需要写入时加密
static void mark_path_encrypt_on_write(const char *path, int should_encrypt) {
    if (!path) return;
    
    pthread_mutex_lock(&fd_table_mutex);
    fd_context_t *current = fd_table;
    while (current) {
        if (current->path && strcmp(current->path, path) == 0) {
            current->should_encrypt_on_write = should_encrypt;
            DEBUG_LOG("标记路径写入加密: %s, 加密=%s", path, should_encrypt ? "是" : "否");
        }
        current = current->next;
    }
    pthread_mutex_unlock(&fd_table_mutex);
}

// 【方案2核心】检查fd是否需要写入时加密
static int should_encrypt_write_for_fd(int fd) {
    fd_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (fd_context_get_info(fd, &ctx)) {
        int result = ctx.should_encrypt_on_write;
        if (ctx.path) free(ctx.path);
        return result;
    }
    return 0;
}

// ==================== 内存映射区域管理 ====================
typedef struct {
    void *addr;                 // 映射地址
    size_t length;              // 映射长度
    int prot;                   // 保护属性
    int original_flags;         // 原始映射标志
    int actual_flags;           // 实际使用的映射标志
    int original_fd;            // 原始文件描述符
    off_t offset;               // 文件偏移
    char *file_path;            // 文件路径
    int is_target_dwg;          // 是否为目标DWG文件
    int is_private_copy;        // 是否为我们创建的私有副本
    bool has_modifications;     // 是否有修改
    void *encrypted_backup;     // 加密备份数据
    size_t backup_size;         // 备份数据大小
    bool should_preserve;       // 是否应该保持映射不被过早销毁
} mmap_region_t;

static mmap_region_t mmap_regions[MAX_MMAP_REGIONS];
static pthread_mutex_t mmap_table_mutex = PTHREAD_MUTEX_INITIALIZER;

static int find_available_mmap_slot(void) {
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == NULL) return i;
    }
    return -1;
}

static mmap_region_t *find_mmap_region_by_addr(void *addr) {
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (!mmap_regions[i].addr) continue;
        char *region_start = (char *)mmap_regions[i].addr;
        char *region_end = region_start + mmap_regions[i].length;
        if ((char *)addr >= region_start && (char *)addr < region_end) {
            return &mmap_regions[i];
        }
    }
    return NULL;
}

static void mark_mmap_modified_by_fd(int fd) {
    pthread_mutex_lock(&mmap_table_mutex);
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr && mmap_regions[i].original_fd == fd) {
            mmap_regions[i].has_modifications = true;
            if (mmap_regions[i].is_target_dwg && mmap_regions[i].is_private_copy) {
                DEBUG_LOG("标记DWG私有副本已修改: addr=%p, fd=%d", mmap_regions[i].addr, fd);
            }
        }
    }
    pthread_mutex_unlock(&mmap_table_mutex);
}

// ==================== XOR加解密算法（高性能版本） ====================
static void xor_encrypt_decrypt_optimized(unsigned char *data, size_t size) {
    size_t i = 0;
    const uint64_t xor_key = 0xFFFFFFFFFFFFFFFFULL;  // 64位XOR密钥
    
    // 批量处理64位数据块
    for (; i + sizeof(uint64_t) <= size; i += sizeof(uint64_t)) {
        uint64_t *data_ptr = (uint64_t *)(data + i);
        *data_ptr ^= xor_key;
    }
    
    // 处理剩余字节
    for (; i < size; ++i) {
        data[i] ^= 0xFF;
    }
}

// ==================== TLS缓冲区管理 ====================
static unsigned char *get_thread_local_buffer(size_t required_size) {
    static __thread unsigned char *buffer = NULL;
    static __thread size_t buffer_capacity = 0;
    
    if (buffer_capacity < required_size) {
        size_t new_capacity = required_size;
        size_t alignment = WRITE_BLOCK_SIZE;
        if (new_capacity % alignment) {
            new_capacity = ((new_capacity / alignment) + 1) * alignment;
        }
        
        unsigned char *new_buffer = realloc(buffer, new_capacity);
        if (!new_buffer) return NULL;
        
        buffer = new_buffer;
        buffer_capacity = new_capacity;
    }
    return buffer;
}

// ==================== 辅助函数：从文件描述符获取路径 ====================
static char *get_path_from_fd(int fd) {
    if (fd < 0) return NULL;
    
    char proc_link[64];
    char file_path[MAX_PATH_LEN];
    snprintf(proc_link, sizeof(proc_link), "/proc/self/fd/%d", fd);
    
    ssize_t path_len = readlink(proc_link, file_path, sizeof(file_path) - 1);
    if (path_len < 0) return NULL;
    
    file_path[path_len] = '\0';
    return strdup(file_path);
}

// ==================== 创建加密备份数据 ====================
static int create_encrypted_backup(mmap_region_t *region) {
    if (!region || !region->addr || region->length == 0) return -1;
    
    // 分配备份内存
    region->encrypted_backup = malloc(region->length);
    if (!region->encrypted_backup) {
        DEBUG_LOG("创建加密备份失败：内存分配失败");
        return -1;
    }
    
    // 复制明文数据
    memcpy(region->encrypted_backup, region->addr, region->length);
    
    // 加密备份数据
    xor_encrypt_decrypt_optimized((unsigned char *)region->encrypted_backup, region->length);
    region->backup_size = region->length;
    
    DEBUG_LOG("创建加密备份成功: addr=%p, 大小=%zu", region->addr, region->length);
    return 0;
}

// ==================== 写回加密数据到文件 ====================
static int write_encrypted_backup_to_file(const char *file_path, const void *encrypted_data, size_t size) {
    if (!file_path || !encrypted_data || size == 0) return -1;

    DEBUG_LOG("开始写回加密数据到文件: 路径=%s, 大小=%zu", file_path, size);

    BEGIN_INTERNAL_IO();
    int fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        DEBUG_LOG("写回失败：无法打开文件 %s - %s", file_path, strerror(errno));
        END_INTERNAL_IO();
        return -1;
    }

    const unsigned char *source = (const unsigned char *)encrypted_data;
    size_t total_written = 0;

    while (total_written < size) {
        size_t chunk_size = (size - total_written > WRITE_BLOCK_SIZE) ?
                           WRITE_BLOCK_SIZE : (size - total_written);

        ssize_t written = write(fd, source + total_written, chunk_size);
        if (written < 0) {
            DEBUG_LOG("写回失败：write错误 - %s", strerror(errno));
            close(fd);
            END_INTERNAL_IO();
            return -1;
        }
        if ((size_t)written != chunk_size) {
            DEBUG_LOG("写回不完整：期望%zu字节，实际%zd字节", chunk_size, written);
            close(fd);
            END_INTERNAL_IO();
            return -1;
        }

        total_written += chunk_size;

        if ((total_written % (WRITE_BLOCK_SIZE * 8)) == 0 || total_written == size) {
            double progress = (double)total_written * 100.0 / (double)size;
            DEBUG_LOG("写回进度: %zu/%zu (%.1f%%)", total_written, size, progress);
        }

        if (total_written < size) {
            sched_yield();
        }
    }

    /* 强制写入磁盘 */
    if (fsync(fd) != 0) {
        DEBUG_LOG("写回后fsync失败: %s - %s", file_path, strerror(errno));
    } else {
        DEBUG_LOG("写回并fsync完成: %s", file_path);
    }

    close(fd);
    END_INTERNAL_IO();
    DEBUG_LOG("加密数据写回完成: 共写入%zu字节", total_written);
    return 0;
}

// 收尾兜底：检查并修正可能的明文块
static void final_seal_if_needed(int fd) {
    fd_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (!fd_context_get_info(fd, &ctx) || !ctx.is_target_dwg) {
        if (ctx.path) free(ctx.path);
        return;
    }
    
    if (!ctx.saw_plain_writes) {
        DEBUG_LOG("fd=%d 未检测到明文写入，跳过收尾检查", fd);
        if (ctx.path) free(ctx.path);
        return;
    }
    
    DEBUG_LOG("开始收尾检查: fd=%d, 路径=%s", fd, ctx.path ? ctx.path : "未知");
    
    BEGIN_INTERNAL_IO();
    
    // 简化实现：读取文件头检查是否为明文
    unsigned char header[64];
    ssize_t read_bytes = pread(fd, header, sizeof(header), 0);
    if (read_bytes > 0) {
        // 检查是否像DWG明文头（简单启发式）
        if (read_bytes >= 6 && memcmp(header, "AC10", 4) == 0) {
            DEBUG_LOG("检测到明文DWG头，进行加密修正");
            for (ssize_t i = 0; i < read_bytes; i++) {
                header[i] ^= 0xFF;
            }
            pwrite(fd, header, read_bytes, 0);
            DEBUG_LOG("收尾修正完成：修正了文件头 %zd 字节", read_bytes);
        }
    }
    
    END_INTERNAL_IO();
    if (ctx.path) free(ctx.path);
}

// 分块内存加解密函数（带内存保护处理）
static int chunked_memory_crypto(void *addr, size_t length, const char *operation_name, 
                                int target_protection) {
    if (!addr || length == 0) return -1;
    
    unsigned char *ptr = (unsigned char *)addr;
    size_t processed = 0;
    
    DEBUG_LOG("开始%s操作: 地址=%p, 长度=%zu字节", operation_name, addr, length);
    
    while (processed < length) {
        size_t current_chunk = (length - processed > MMAP_CRYPT_BLOCK) ? 
                              MMAP_CRYPT_BLOCK : (length - processed);
        
        void *aligned_start = NULL;
        size_t aligned_length = 0;
        align_to_pages(ptr + processed, current_chunk, &aligned_start, &aligned_length);
        
        // 临时设置为可读写
        if (mprotect(aligned_start, aligned_length, PROT_READ | PROT_WRITE) != 0) {
            DEBUG_LOG("%s失败：无法设置内存保护为可写 - %s", operation_name, strerror(errno));
            return -1;
        }
        
        // 执行加密/解密操作
        xor_encrypt_decrypt_optimized(ptr + processed, current_chunk);
        
        // 恢复原始内存保护
        if (mprotect(aligned_start, aligned_length, target_protection) != 0) {
            DEBUG_LOG("警告：%s后无法恢复内存保护 - %s", operation_name, strerror(errno));
        }
        
        processed += current_chunk;
        
        // 定期报告进度
        if ((processed % (MMAP_CRYPT_BLOCK * 4)) == 0 || processed == length) {
            double progress = (double)processed * 100.0 / (double)length;
            DEBUG_LOG("%s进度: %zu/%zu (%.1f%%)", operation_name, processed, length, progress);
        }
        
        if (processed < length) {
            sched_yield();
        }
    }
    
    DEBUG_LOG("%s操作完成", operation_name);
    return 0;
}

static int decrypt_memory_region(void *addr, size_t length, int target_protection) {
    return chunked_memory_crypto(addr, length, "内存解密", target_protection);
}

// 原地在同一 inode 上进行整文件加密覆盖（避免使用临时文件 rename）
// 这样可以保持 inode 不变，避免 CAD 检测到“文件被外部替换/保护”。
// 注意：此实现会逐块读取原文件并在同一偏移写回加密块，使用 pread/pwrite 保证线程安全。
// 原子替换：对现有文件做整文件加密并原子覆盖（内部IO短路保护）
static int encrypt_entire_file_inplace(const char *path) {
    if (!path) return -1;
    
    DEBUG_LOG("开始整文件加密替换: %s", path);
    
    // 检查是否启用整文件加密
    if (!ENABLE_FINAL_FILE_ENCRYPTION) {
        DEBUG_LOG("整文件加密已禁用，跳过: %s", path);
        return 0;
    }
    
    BEGIN_INTERNAL_IO();

    // 以读写打开目标文件，保持文件 inode 不变
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        DEBUG_LOG("encrypt_inplace: 无法以读写方式打开文件 %s - %s", path, strerror(errno));
        END_INTERNAL_IO();
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        DEBUG_LOG("encrypt_inplace: fstat失败 %s - %s", path, strerror(errno));
        close(fd);
        END_INTERNAL_IO();
        return -1;
    }
    off_t filesize = st.st_size;

    // 分配缓冲区（按 WRITE_BLOCK_SIZE 分块）
    size_t buf_sz = WRITE_BLOCK_SIZE;
    unsigned char *buf = malloc(buf_sz);
    if (!buf) {
        DEBUG_LOG("encrypt_inplace: 内存分配失败");
        close(fd);
        END_INTERNAL_IO();
        return -1;
    }

    off_t offset = 0;
    while (offset < filesize) {
        size_t toread = (size_t)((filesize - offset) > (off_t)buf_sz ? buf_sz : (size_t)(filesize - offset));

        // 从原文件特定偏移读取原始数据
        ssize_t r = pread(fd, buf, toread, offset);
        if (r < 0) {
            DEBUG_LOG("encrypt_inplace: pread失败 offset=%ld - %s", (long)offset, strerror(errno));
            free(buf);
            close(fd);
            END_INTERNAL_IO();
            return -1;
        } else if (r == 0) {
            // 文件比预期小，退出循环
            break;
        }

        // 对读取的数据进行异或加密
        xor_encrypt_decrypt_optimized(buf, (size_t)r);

        // 将加密后的数据写回同一偏移（in-place）
        ssize_t w = pwrite(fd, buf, r, offset);
        if (w != r) {
            DEBUG_LOG("encrypt_inplace: pwrite失败 offset=%ld expect=%zd actual=%zd - %s",
                      (long)offset, r, w, strerror(errno));
            free(buf);
            close(fd);
            END_INTERNAL_IO();
            return -1;
        }

        offset += r;
    }

    // 强制写盘并关闭
    if (fsync(fd) != 0) {
        DEBUG_LOG("encrypt_inplace: fsync失败 %s - %s", path, strerror(errno));
        // 仍然继续尝试关闭
    } else {
        DEBUG_LOG("encrypt_inplace: 已在原 inode 上写入并 fsync 完成: %s", path);
    }

    free(buf);
    close(fd);

    END_INTERNAL_IO();
    return 0;
}

// ==================== 映射区域跟踪函数 ====================
static void track_mmap_region(void *addr, size_t length, int prot, int original_flags, 
                             int actual_flags, int original_fd, off_t offset, 
                             int is_target, int is_private_copy, const char *path) {
    if (!addr) return;
    
    pthread_mutex_lock(&mmap_table_mutex);
    int slot = find_available_mmap_slot();
    if (slot >= 0) {
        mmap_regions[slot].addr = addr;
        mmap_regions[slot].length = length;
        mmap_regions[slot].prot = prot;
        mmap_regions[slot].original_flags = original_flags;
        mmap_regions[slot].actual_flags = actual_flags;
        mmap_regions[slot].original_fd = original_fd;
        mmap_regions[slot].offset = offset;
        mmap_regions[slot].is_target_dwg = is_target;
        mmap_regions[slot].is_private_copy = is_private_copy;
        mmap_regions[slot].has_modifications = false;
        mmap_regions[slot].encrypted_backup = NULL;
        mmap_regions[slot].backup_size = 0;
        mmap_regions[slot].should_preserve = (is_target && is_private_copy);
        if (path) mmap_regions[slot].file_path = strdup(path);
        
        DEBUG_LOG("映射区域跟踪: 槽位=%d, 地址=%p, 长度=%zu, 原始fd=%d, 目标DWG=%s, 私有副本=%s",
                 slot, addr, length, original_fd, 
                 is_target ? "是" : "否", is_private_copy ? "是" : "否");
    } else {
        DEBUG_LOG("警告：无可用槽位跟踪映射区域 地址=%p 长度=%zu", addr, length);
    }
    pthread_mutex_unlock(&mmap_table_mutex);
}

static void untrack_mmap_region(void *addr, size_t length) {
    pthread_mutex_lock(&mmap_table_mutex);
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == addr && mmap_regions[i].length == length) {
            DEBUG_LOG("取消映射区域跟踪: 地址=%p, 长度=%zu", addr, length);
            
            // 释放加密备份数据
            if (mmap_regions[i].encrypted_backup) {
                free(mmap_regions[i].encrypted_backup);
            }
            
            if (mmap_regions[i].file_path) {
                free(mmap_regions[i].file_path);
            }
            memset(&mmap_regions[i], 0, sizeof(mmap_regions[i]));
            break;
        }
    }
    pthread_mutex_unlock(&mmap_table_mutex);
}

// 文件关闭时写回所有相关私有副本
static void flush_private_copies_on_close(int original_fd) {
    if (!ENABLE_FINAL_FILE_ENCRYPTION) {
        DEBUG_LOG("已禁用close时私有副本写回: fd=%d", original_fd);
        return;
    }
    
    pthread_mutex_lock(&mmap_table_mutex);
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        mmap_region_t *region = &mmap_regions[i];
        if (!region->addr || region->original_fd != original_fd) continue;
        if (!region->is_target_dwg || !region->is_private_copy) continue;
        
        DEBUG_LOG("文件关闭时处理私有副本: 原始fd=%d, 地址=%p, 长度=%zu", 
                 original_fd, region->addr, region->length);
        
        // 创建加密备份并写回文件
        if (region->file_path) {
            if (create_encrypted_backup(region) == 0) {
                if (write_encrypted_backup_to_file(region->file_path, 
                                                  region->encrypted_backup, 
                                                  region->backup_size) == 0) {
                    DEBUG_LOG("close时私有副本写回成功: %s", region->file_path);
                    region->has_modifications = false;
                    // 写回成功后，允许解除映射
                    region->should_preserve = false;
                } else {
                    DEBUG_LOG("close时私有副本写回失败: %s", region->file_path);
                }
            }
        }
    }
    pthread_mutex_unlock(&mmap_table_mutex);
}

// ==================== 系统调用Hook实现 ====================

// open系列函数Hook
int open(const char *pathname, int flags, ...) {
    static int (*real_open)(const char *, int, mode_t) = NULL;
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
        DEBUG_LOG("open Hook已初始化: real_open=%p", real_open);
    }
    
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    
    // 【方案2】检查是否为临时文件，如果是则在日志中标记
    if (pathname && is_temporary_file(pathname)) {
        DEBUG_LOG("【方案2】检测到临时文件（open）: %s", pathname);
    }
    
    int fd = real_open(pathname, flags, mode);
    if (fd >= 0) {
        fd_context_add(fd, pathname);
    }
    return fd;
}

int open64(const char *pathname, int flags, ...) {
    static int (*real_open64)(const char *, int, mode_t) = NULL;
    if (!real_open64) {
        real_open64 = dlsym(RTLD_NEXT, "open64");
        DEBUG_LOG("open64 Hook已初始化: real_open64=%p", real_open64);
    }
    
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    
    // 【方案2】检查是否为临时文件
    if (pathname && is_temporary_file(pathname)) {
        DEBUG_LOG("【方案2】检测到临时文件（open64）: %s", pathname);
    }
    
    int fd = real_open64(pathname, flags, mode);
    if (fd >= 0) {
        fd_context_add(fd, pathname);
    }
    return fd;
}

int creat(const char *pathname, mode_t mode) {
    static int (*real_creat)(const char *, mode_t) = NULL;
    if (!real_creat) {
        real_creat = dlsym(RTLD_NEXT, "creat");
        DEBUG_LOG("creat Hook已初始化: real_creat=%p", real_creat);
    }
    
    // 【方案2】检查是否为临时文件
    if (pathname && is_temporary_file(pathname)) {
        DEBUG_LOG("【方案2】检测到临时文件（creat）: %s", pathname);
    }
    
    int fd = real_creat(pathname, mode);
    if (fd >= 0) {
        fd_context_add(fd, pathname);
    }
    return fd;
}

int close(int fd) {
    static int (*real_close)(int) = NULL;
    if (!real_close) {
        real_close = dlsym(RTLD_NEXT, "close");
        DEBUG_LOG("close Hook已初始化: real_close=%p", real_close);
    }
    
    // 内部IO护栏
    if (is_internal_io()) {
        return real_close(fd);
    }
    
    // 检查是否为目标DWG文件，如果是则先写回相关私有副本
    fd_context_t ctx;
    if (fd_context_get_info(fd, &ctx)) {
        if (ctx.is_target_dwg) {
            DEBUG_LOG("关闭目标DWG文件，执行收尾检查: fd=%d, 路径=%s", 
                     fd, ctx.path ? ctx.path : "(未知)");
            final_seal_if_needed(fd);
            if (ENABLE_FINAL_FILE_ENCRYPTION) {
                flush_private_copies_on_close(fd);
            }
        }
        if (ctx.path) free(ctx.path);
    }
    
    fd_context_remove(fd);
    return real_close(fd);
}

// read系列函数Hook（透明解密返回给应用程序）
ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real_read)(int, void *, size_t) = NULL;
    if (!real_read) {
        real_read = dlsym(RTLD_NEXT, "read");
        DEBUG_LOG("read Hook已初始化: real_read=%p", real_read);
    }
    
    // 内部IO护栏
    if (is_internal_io()) {
        return real_read(fd, buf, count);
    }
    
    ssize_t result = real_read(fd, buf, count);
    if (result <= 0 || !buf) return result;
    
    fd_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (fd_context_get_info(fd, &ctx) && ctx.is_target_dwg) {
        DEBUG_LOG("=====【读取Hook】fd=%d, 文件=%s, 字节数=%zd", 
                 fd, ctx.path ? ctx.path : "未知", result);
        
        if ((size_t)result <= 4096) {
            log_hex_preview("解密前数据", (unsigned char *)buf, result);
        }
        
        // 对读取的密文数据进行解密，返回明文给应用程序
        xor_encrypt_decrypt_optimized((unsigned char *)buf, result);
        
        if ((size_t)result <= 4096) {
            log_hex_preview("解密后数据", (unsigned char *)buf, result);
        }
    }
    if (ctx.path) free(ctx.path);
    return result;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    static size_t (*real_fread)(void *, size_t, size_t, FILE *) = NULL;
    if (!real_fread) {
        real_fread = dlsym(RTLD_NEXT, "fread");
        DEBUG_LOG("fread Hook已初始化: real_fread=%p", real_fread);
    }
    
    // 内部IO护栏
    if (is_internal_io()) {
        return real_fread(ptr, size, nmemb, stream);
    }
    
    size_t result = real_fread(ptr, size, nmemb, stream);
    if (result == 0 || !ptr) return result;
    
    int fd = fileno(stream);
    if (fd >= 0) {
        fd_context_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        if (fd_context_get_info(fd, &ctx) && ctx.is_target_dwg) {
            size_t total_bytes = result * size;
            DEBUG_LOG("=====【fread Hook】fd=%d, 文件=%s, 字节数=%zu", 
                     fd, ctx.path ? ctx.path : "未知", total_bytes);
            
            if (total_bytes <= 4096) {
                log_hex_preview("fread解密前", (unsigned char *)ptr, total_bytes);
            }
            
            xor_encrypt_decrypt_optimized((unsigned char *)ptr, total_bytes);
            
            if (total_bytes <= 4096) {
                log_hex_preview("fread解密后", (unsigned char *)ptr, total_bytes);
            }
        }
        if (ctx.path) free(ctx.path);
    }
    return result;
}

// 【方案2增强】write系列函数Hook（加密后写入磁盘）
ssize_t write(int fd, const void *buf, size_t count) {
    static ssize_t (*real_write)(int, const void *, size_t) = NULL;
    if (!real_write) {
        real_write = dlsym(RTLD_NEXT, "write");
        DEBUG_LOG("write Hook已初始化: real_write=%p", real_write);
    }
    
    // 内部IO护栏
    if (is_internal_io()) {
        return real_write(fd, buf, count);
    }
    
    if (count == 0 || !buf) return real_write(fd, buf, count);
    
    // 【方案2】检查是否需要加密写入（包含临时文件和目标DWG文件）
    if (!should_encrypt_write_for_fd(fd)) {
        return real_write(fd, buf, count);
    }
    
    // 标记见过明文写入
    pthread_mutex_lock(&fd_table_mutex);
    fd_context_t *current = fd_table;
    while (current) {
        if (current->fd == fd) {
            current->saw_plain_writes = 1;
            break;
        }
        current = current->next;
    }
    pthread_mutex_unlock(&fd_table_mutex);
    
    DEBUG_LOG("=====【写入Hook】fd=%d, 大小=%zu字节 (方案2在线加密)", fd, count);
    
    const unsigned char *source = (const unsigned char *)buf;
    ssize_t total_written = 0;
    
    while (total_written < (ssize_t)count) {
        size_t chunk_size = (count - total_written > WRITE_BLOCK_SIZE) ? 
                           WRITE_BLOCK_SIZE : (count - total_written);
        
        unsigned char *temp_buffer = get_thread_local_buffer(chunk_size);
        if (!temp_buffer) {
            errno = ENOMEM;
            return -1;
        }
        
        // 【方案2】在线异或加密
        memcpy(temp_buffer, source + total_written, chunk_size);
        xor_encrypt_decrypt_optimized(temp_buffer, chunk_size);
        
        if (total_written == 0 && chunk_size >= 16) {
            log_hex_preview("【方案2】加密前数据", source, chunk_size > 64 ? 64 : chunk_size);
            log_hex_preview("【方案2】加密后数据", temp_buffer, chunk_size > 64 ? 64 : chunk_size);
        }
        
        ssize_t written;
        BEGIN_INTERNAL_IO();
        written = real_write(fd, temp_buffer, chunk_size);
        END_INTERNAL_IO();
        
        if (written <= 0) {
            return (written == 0) ? total_written : written;
        }
        
        total_written += written;
    }
    
    // 标记相关映射已修改
    mark_mmap_modified_by_fd(fd);
    return total_written;
}

ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset) {
    static ssize_t (*real_pwrite64)(int, const void *, size_t, off_t) = NULL;
    if (!real_pwrite64) {
        real_pwrite64 = dlsym(RTLD_NEXT, "pwrite64");
        DEBUG_LOG("pwrite64 Hook已初始化: real_pwrite64=%p", real_pwrite64);
    }
    
    // 内部IO护栏
    if (is_internal_io()) {
        return real_pwrite64(fd, buf, count, offset);
    }
    
    if (count == 0 || !buf) return real_pwrite64(fd, buf, count, offset);
    
    // 【方案2】检查是否需要加密写入
    if (!should_encrypt_write_for_fd(fd)) {
        return real_pwrite64(fd, buf, count, offset);
    }
    
    DEBUG_LOG("=====【pwrite64 Hook】fd=%d, 偏移=%ld, 大小=%zu (方案2在线加密)", 
             fd, (long)offset, count);
    
    const unsigned char *source = (const unsigned char *)buf;
    ssize_t total_written = 0;
    off_t current_offset = offset;
    
    while (total_written < (ssize_t)count) {
        size_t chunk_size = (count - total_written > WRITE_BLOCK_SIZE) ? 
                           WRITE_BLOCK_SIZE : (count - total_written);
        
        unsigned char *temp_buffer = get_thread_local_buffer(chunk_size);
        if (!temp_buffer) {
            errno = ENOMEM;
            return -1;
        }
        
        // 【方案2】加密处理
        memcpy(temp_buffer, source + total_written, chunk_size);
        xor_encrypt_decrypt_optimized(temp_buffer, chunk_size);
        
        ssize_t written;
        BEGIN_INTERNAL_IO();
        written = real_pwrite64(fd, temp_buffer, chunk_size, current_offset);
        END_INTERNAL_IO();
        
        if (written <= 0) {
            return (written == 0) ? total_written : written;
        }
        
        total_written += written;
        current_offset += written;
    }
    
    mark_mmap_modified_by_fd(fd);
    return total_written;
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
    static ssize_t (*real_pwrite)(int, const void *, size_t, off_t) = NULL;
    if (!real_pwrite) {
        real_pwrite = dlsym(RTLD_NEXT, "pwrite");
        DEBUG_LOG("pwrite Hook已初始化: real_pwrite=%p", real_pwrite);
    }
    
    // 内部IO护栏
    if (is_internal_io()) {
        return real_pwrite(fd, buf, count, offset);
    }
    
    if (count == 0 || !buf) return real_pwrite(fd, buf, count, offset);
    
    // 【方案2】检查是否需要加密写入
    if (!should_encrypt_write_for_fd(fd)) {
        return real_pwrite(fd, buf, count, offset);
    }
    
    DEBUG_LOG("=====【pwrite Hook】fd=%d, 偏移=%ld, 大小=%zu (方案2在线加密)", 
             fd, (long)offset, count);
    
    const unsigned char *source = (const unsigned char *)buf;
    ssize_t total_written = 0;
    off_t current_offset = offset;
    
    while (total_written < (ssize_t)count) {
        size_t chunk_size = (count - total_written > WRITE_BLOCK_SIZE) ? 
                           WRITE_BLOCK_SIZE : (count - total_written);
        
        unsigned char *temp_buffer = get_thread_local_buffer(chunk_size);
        if (!temp_buffer) {
            errno = ENOMEM;
            return -1;
        }
        
        // 【方案2】加密处理
        memcpy(temp_buffer, source + total_written, chunk_size);
        xor_encrypt_decrypt_optimized(temp_buffer, chunk_size);
        
        ssize_t written;
        BEGIN_INTERNAL_IO();
        written = real_pwrite(fd, temp_buffer, chunk_size, current_offset);
        END_INTERNAL_IO();
        
        if (written <= 0) {
            return (written == 0) ? total_written : written;
        }
        
        total_written += written;
        current_offset += written;
    }
    
    mark_mmap_modified_by_fd(fd);
    return total_written;
}

// 【方案2增强】fwrite Hook
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    static size_t (*real_fwrite)(const void *, size_t, size_t, FILE *) = NULL;
    if (!real_fwrite) {
        real_fwrite = dlsym(RTLD_NEXT, "fwrite");
        DEBUG_LOG("fwrite Hook已初始化: real_fwrite=%p", real_fwrite);
    }
    
    // 内部IO护栏
    if (is_internal_io()) {
        return real_fwrite(ptr, size, nmemb, stream);
    }
    
    if (!stream || !ptr || size == 0 || nmemb == 0) {
        return real_fwrite(ptr, size, nmemb, stream);
    }
    
    int fd = fileno(stream);
    if (fd < 0) return real_fwrite(ptr, size, nmemb, stream);
    
    // 【方案2】检查是否需要加密写入
    if (!should_encrypt_write_for_fd(fd)) {
        return real_fwrite(ptr, size, nmemb, stream);
    }
    
    size_t total_bytes = size * nmemb;
    DEBUG_LOG("=====【fwrite Hook】fd=%d, 字节数=%zu (方案2在线加密)", fd, total_bytes);
    DEBUG_LOG("【方案2执行】对fwrite数据进行实时XOR加密");
    
    const unsigned char *source = (const unsigned char *)ptr;
    size_t written_bytes = 0;
    size_t written_elements = 0;
    
    while (written_bytes < total_bytes) {
        size_t chunk_size = (total_bytes - written_bytes > WRITE_BLOCK_SIZE) ? 
                           WRITE_BLOCK_SIZE : (total_bytes - written_bytes);
        
        unsigned char *temp_buffer = get_thread_local_buffer(chunk_size);
        if (!temp_buffer) {
            DEBUG_LOG("fwrite缓冲区分配失败");
            return 0;
        }
        
        // 【方案2】加密处理
        memcpy(temp_buffer, source + written_bytes, chunk_size);
        xor_encrypt_decrypt_optimized(temp_buffer, chunk_size);
        
        size_t chunk_elements = chunk_size / size;
        if (chunk_elements == 0 && chunk_size > 0) chunk_elements = 1;
        
        size_t written;
        BEGIN_INTERNAL_IO();
        written = real_fwrite(temp_buffer, size, chunk_elements, stream);
        END_INTERNAL_IO();
        
        if (written == 0) {
            DEBUG_LOG("fwrite分块写入失败");
            return written_elements;
        }
        
        written_bytes += written * size;
        written_elements += written;
    }
    
    mark_mmap_modified_by_fd(fd);
    return written_elements;
}

// ==================== 核心mmap Hook（关键功能） ====================
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    static void *(*real_mmap)(void *, size_t, int, int, int, off_t) = NULL;
    if (!real_mmap) {
        real_mmap = dlsym(RTLD_NEXT, "mmap");
        DEBUG_LOG("mmap Hook已初始化: real_mmap=%p", real_mmap);
    }
    
    // 检查是否为目标DWG文件
    fd_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    int is_target = 0;
    char *file_path = NULL;
    
    if (fd >= 0) {
        if (fd_context_get_info(fd, &ctx)) {
            is_target = ctx.is_target_dwg;
            if (ctx.path) file_path = strdup(ctx.path);
            if (ctx.path) free(ctx.path);
        } else {
            // 尝试从文件描述符获取路径
            char *path = get_path_from_fd(fd);
            if (path) {
                is_target = is_target_dwg_file(path);
                file_path = path;
                DEBUG_LOG("从fd推断文件类型: fd=%d, 路径=%s, 是否目标DWG=%s", 
                         fd, path, is_target ? "是" : "否");
            }
        }
    }
    
    if (is_target && (flags & MAP_SHARED)) {
        // 【方案1】关键策略：将MAP_SHARED替换为MAP_PRIVATE
        // 这样创建私有副本，不会影响内核页缓存和磁盘文件
        int modified_flags = (flags & ~MAP_SHARED) | MAP_PRIVATE;
        
        DEBUG_LOG("【方案1】检测到目标DWG的MAP_SHARED映射，转换为MAP_PRIVATE私有副本");
        DEBUG_LOG("【方案1生效】创建私有副本避免直接修改磁盘文件");
        DEBUG_LOG("映射参数: 地址=%p, 长度=%zu, 保护=%d, 原始标志=0x%x, 修改标志=0x%x, fd=%d", 
                 addr, length, prot, flags, modified_flags, fd);
        
        void *result = real_mmap(addr, length, prot, modified_flags, fd, offset);
        if (result == MAP_FAILED) {
            DEBUG_LOG("私有映射创建失败: %s", strerror(errno));
            if (file_path) free(file_path);
            return result;
        }
        
        // 跟踪这个私有副本映射
        track_mmap_region(result, length, prot, flags, modified_flags, fd, 
                         offset, 1, 1, file_path);
        
        // 在私有副本上进行分块解密（仅影响进程内存，不影响磁盘）
        DEBUG_LOG("开始对私有副本进行流式解密处理");
        if (decrypt_memory_region(result, length, prot) != 0) {
            DEBUG_LOG("私有副本解密失败");
        } else {
            DEBUG_LOG("私有副本解密成功：地址=%p, 长度=%zu", result, length);
        }
        
        if (file_path) free(file_path);
        return result;
        
    } else {
        // 非目标文件或非MAP_SHARED的常规处理
        void *result = real_mmap(addr, length, prot, flags, fd, offset);
        if (result == MAP_FAILED) {
            if (file_path) free(file_path);
            return result;
        }
        
        if (is_target) {
            // 目标DWG但不是MAP_SHARED（如MAP_PRIVATE），仍需解密
            track_mmap_region(result, length, prot, flags, flags, fd, 
                             offset, 1, 0, file_path);
            
            DEBUG_LOG("对目标DWG非共享映射进行解密: 地址=%p, 长度=%zu", result, length);
            if (decrypt_memory_region(result, length, prot) != 0) {
                DEBUG_LOG("目标DWG映射解密失败");
            }
        } else {
            // 非目标文件，仅做基本跟踪
            track_mmap_region(result, length, prot, flags, flags, fd, 
                             offset, 0, 0, file_path);
        }
        
        if (file_path) free(file_path);
        return result;
    }
}

// ==================== msync Hook（私有副本同步机制） ====================
int msync(void *addr, size_t length, int flags) {
    static int (*real_msync)(void *, size_t, int) = NULL;
    if (!real_msync) {
        real_msync = dlsym(RTLD_NEXT, "msync");
        DEBUG_LOG("msync Hook已初始化: real_msync=%p", real_msync);
    }
    
    DEBUG_LOG("内存同步请求: 地址=%p, 长度=%zu, 标志=0x%x", addr, length, flags);
    
    // 对于私有副本，msync不需要写回磁盘，因为私有副本的修改不会影响原文件
    // 只有在明确需要保存时（如程序退出、显式保存操作）才写回
    
    return real_msync(addr, length, flags);
}

// ==================== munmap Hook（解除映射前确保数据持久化） ====================
int munmap(void *addr, size_t length) {
    static int (*real_munmap)(void *, size_t) = NULL;
    if (!real_munmap) {
        real_munmap = dlsym(RTLD_NEXT, "munmap");
        DEBUG_LOG("munmap Hook已初始化: real_munmap=%p", real_munmap);
    }
    
    DEBUG_LOG("解除内存映射: 地址=%p, 长度=%zu", addr, length);
    
    // 检查是否为需要保持的私有副本，如果是则先备份再放行
    pthread_mutex_lock(&mmap_table_mutex);
    mmap_region_t *region = NULL;
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == addr && mmap_regions[i].length == length) {
            region = &mmap_regions[i];
            break;
        }
    }
    
    if (region && region->is_target_dwg && region->should_preserve) {
        DEBUG_LOG("【方案1】DWG私有副本解除映射前先备份: 地址=%p, 长度=%zu, fd=%d", 
                 addr, length, region->original_fd);
        // 在放行前先把内容备份（并加密到内存）
        if (!region->encrypted_backup && region->length) {
            create_encrypted_backup(region);
        }
        // 备份完后，可以放行 munmap
        region->should_preserve = false;
    }
    pthread_mutex_unlock(&mmap_table_mutex);
    
    int result = real_munmap(addr, length);
    if (result == 0) {
        untrack_mmap_region(addr, length);
    } else {
        DEBUG_LOG("munmap执行失败: %s", strerror(errno));
    }
    return result;
}

// ==================== fsync/fdatasync Hook（显式同步时处理私有副本） ====================
int fsync(int fd) {
    static int (*real_fsync)(int) = NULL;
    if (!real_fsync) {
        real_fsync = dlsym(RTLD_NEXT, "fsync");
        DEBUG_LOG("fsync Hook已初始化: real_fsync=%p", real_fsync);
    }
    
    // 内部IO护栏
    if (is_internal_io()) {
        return real_fsync(fd);
    }
    
    DEBUG_LOG("文件同步请求: fd=%d", fd);
    
    // 检查是否为目标DWG文件的fsync
    fd_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (fd_context_get_info(fd, &ctx) && ctx.is_target_dwg) {
        DEBUG_LOG("目标DWG文件同步: fd=%d, 路径=%s", fd, ctx.path ? ctx.path : "(未知)");
        
        // 执行收尾检查
        final_seal_if_needed(fd);
        
        // 如果启用了整文件回写，则执行
        if (ENABLE_FINAL_FILE_ENCRYPTION) {
            pthread_mutex_lock(&mmap_table_mutex);
            for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
                mmap_region_t *region = &mmap_regions[i];
                if (!region->addr) continue;
                
                if (region->original_fd == fd && region->is_target_dwg && 
                    region->is_private_copy) {
                    DEBUG_LOG("fsync时强制写回私有副本: fd=%d, 地址=%p, 长度=%zu", 
                             fd, region->addr, region->length);
                    
                    if (region->file_path) {
                        if (create_encrypted_backup(region) == 0) {
                            if (write_encrypted_backup_to_file(region->file_path, 
                                                              region->encrypted_backup, 
                                                              region->backup_size) == 0) {
                                DEBUG_LOG("fsync时私有副本写回成功: %s", region->file_path);
                                region->has_modifications = false;
                                region->should_preserve = false;
                            } else {
                                DEBUG_LOG("fsync时私有副本写回失败: %s", region->file_path);
                            }
                        }
                    }
                }
            }
            pthread_mutex_unlock(&mmap_table_mutex);
        }
    }
    if (ctx.path) free(ctx.path);
    
    int result = real_fsync(fd);
    if (result != 0) {
        DEBUG_LOG("fsync执行失败: %s", strerror(errno));
    }
    return result;
}

int fdatasync(int fd) {
    static int (*real_fdatasync)(int) = NULL;
    if (!real_fdatasync) {
        real_fdatasync = dlsym(RTLD_NEXT, "fdatasync");
        DEBUG_LOG("fdatasync Hook已初始化: real_fdatasync=%p", real_fdatasync);
    }
    
    // 内部IO护栏
    if (is_internal_io()) {
        return real_fdatasync(fd);
    }
    
    DEBUG_LOG("文件数据同步请求: fd=%d", fd);
    
    // 检查是否为目标DWG文件的fdatasync
    fd_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (fd_context_get_info(fd, &ctx) && ctx.is_target_dwg) {
        DEBUG_LOG("目标DWG文件数据同步: fd=%d, 路径=%s", fd, ctx.path ? ctx.path : "(未知)");
        
        // 执行收尾检查
        final_seal_if_needed(fd);
        
        // 如果启用了整文件回写，则执行
        if (ENABLE_FINAL_FILE_ENCRYPTION) {
            pthread_mutex_lock(&mmap_table_mutex);
            for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
                mmap_region_t *region = &mmap_regions[i];
                if (!region->addr) continue;
                
                if (region->original_fd == fd && region->is_target_dwg && 
                    region->is_private_copy) {
                    DEBUG_LOG("fdatasync时强制写回私有副本: fd=%d, 地址=%p, 长度=%zu", 
                             fd, region->addr, region->length);
                    
                    if (region->file_path) {
                        if (create_encrypted_backup(region) == 0) {
                            if (write_encrypted_backup_to_file(region->file_path, 
                                                              region->encrypted_backup, 
                                                              region->backup_size) == 0) {
                                DEBUG_LOG("fdatasync时私有副本写回成功: %s", region->file_path);
                                region->has_modifications = false;
                            } else {
                                DEBUG_LOG("fdatasync时私有副本写回失败: %s", region->file_path);
                            }
                        }
                    }
                }
            }
            pthread_mutex_unlock(&mmap_table_mutex);
        }
    }
    if (ctx.path) free(ctx.path);
    
    int result = real_fdatasync(fd);
    if (result != 0) {
        DEBUG_LOG("fdatasync执行失败: %s", strerror(errno));
    }
    return result;
}

// ==================== rename系列Hook（监控文件重命名操作） ====================
int rename(const char *oldpath, const char *newpath) {
    static int (*real_rename)(const char *, const char *) = NULL;
    if (!real_rename) {
        real_rename = dlsym(RTLD_NEXT, "rename");
        DEBUG_LOG("rename Hook已初始化: real_rename=%p", real_rename);
    }

    // 内部IO护栏
    if (is_internal_io()) {
        return real_rename(oldpath, newpath);
    }

    if (oldpath && newpath) {
        if (is_target_dwg_file(oldpath) || is_target_dwg_file(newpath)) {
            DEBUG_LOG("DWG文件重命名操作: '%s' -> '%s'", oldpath, newpath);
        }
        // 【方案2】临时文件重命名为目标DWG文件
        if (is_temporary_file(oldpath) && is_target_dwg_file(newpath)) {
            DEBUG_LOG("【方案2】检测到临时文件保存为DWG: '%s' -> '%s'", oldpath, newpath);
        }
    }

    // 先执行真实的重命名
    int result = real_rename(oldpath, newpath);
    if (result != 0) {
        DEBUG_LOG("文件重命名失败: %s", strerror(errno));
        return result;
    }

    // 重命名成功后的处理
    if (oldpath && newpath) {
        if (is_target_dwg_file(newpath)) {
            DEBUG_LOG("检测到保存操作：临时文件 -> DWG文件");
            
            // 【方案2】标记新路径需要在写入时加密
            mark_path_encrypt_on_write(newpath, 1);
            
            // 如果启用了整文件回写，则执行（默认禁用）
            if (ENABLE_FINAL_FILE_ENCRYPTION) {
                pthread_mutex_lock(&mmap_table_mutex);
                for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
                    mmap_region_t *region = &mmap_regions[i];
                    if (!region->addr || !region->is_target_dwg || !region->is_private_copy) continue;

                    DEBUG_LOG("【方案1】rename时强制写回私有副本: addr=%p, 长度=%zu",
                              region->addr, region->length);

                    // 写回期间避免被提前解除映射
                    bool prev_preserve = region->should_preserve;
                    region->should_preserve = true;

                    if (create_encrypted_backup(region) == 0) {
                        if (write_encrypted_backup_to_file(newpath,
                                                          region->encrypted_backup,
                                                          region->backup_size) == 0) {
                            DEBUG_LOG("rename时私有副本写回成功: %s", newpath);
                            region->has_modifications = false;

                            if (region->file_path) free(region->file_path);
                            region->file_path = strdup(newpath);
                        } else {
                            DEBUG_LOG("rename时私有副本写回失败: %s", newpath);
                        }
                    }

                    // 恢复 preserve 标志
                    region->should_preserve = prev_preserve;
                }
                pthread_mutex_unlock(&mmap_table_mutex);
            } else {
                // 【方案1】仅保留私有副本，延迟到 fsync/close 再处理
                pthread_mutex_lock(&mmap_table_mutex);
                for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
                    mmap_region_t *region = &mmap_regions[i];
                    if (region->addr && region->is_target_dwg && region->is_private_copy) {
                        region->should_preserve = true;
                        if (region->file_path) free(region->file_path);
                        region->file_path = strdup(newpath);
                        DEBUG_LOG("【方案1】标记私有副本延迟处理: addr=%p, 新路径=%s", region->addr, newpath);
                    }
                }
                pthread_mutex_unlock(&mmap_table_mutex);
            }

            // 在rename完成后对目标文件做整文件加密（兜底保护）
            if (encrypt_entire_file_inplace(newpath) == 0) {
                DEBUG_LOG("rename后整文件加密替换完成: %s", newpath);
            } else {
                DEBUG_LOG("rename后整文件加密替换失败: %s", newpath);
            }
        }
    }

    return result;
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    static int (*real_renameat)(int, const char *, int, const char *) = NULL;
    if (!real_renameat) {
        real_renameat = dlsym(RTLD_NEXT, "renameat");
        DEBUG_LOG("renameat Hook已初始化: real_renameat=%p", real_renameat);
    }

    // 内部IO护栏
    if (is_internal_io()) {
        return real_renameat(olddirfd, oldpath, newdirfd, newpath);
    }

    if (oldpath && newpath) {
        if (is_target_dwg_file(oldpath) || is_target_dwg_file(newpath)) {
            DEBUG_LOG("DWG文件重命名操作（at版本）: '%s' -> '%s'", oldpath, newpath);
        }
        // 【方案2】临时文件重命名为目标DWG文件
        if (is_temporary_file(oldpath) && is_target_dwg_file(newpath)) {
            DEBUG_LOG("【方案2】检测到临时文件保存为DWG（at版本）: '%s' -> '%s'", oldpath, newpath);
        }
    }

    // 先执行真实的重命名
    int result = real_renameat(olddirfd, oldpath, newdirfd, newpath);
    if (result != 0) {
        DEBUG_LOG("文件重命名（at版本）失败: %s", strerror(errno));
        return result;
    }

    // 重命名成功后的处理
    if (oldpath && newpath) {
        if (is_target_dwg_file(newpath)) {
            DEBUG_LOG("检测到保存操作（at版本）：临时文件 -> DWG文件");
            
            // 【方案2】标记新路径需要在写入时加密
            mark_path_encrypt_on_write(newpath, 1);
            
            // 如果启用了整文件回写，则执行（默认禁用）
            if (ENABLE_FINAL_FILE_ENCRYPTION) {
                pthread_mutex_lock(&mmap_table_mutex);
                for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
                    mmap_region_t *region = &mmap_regions[i];
                    if (!region->addr || !region->is_target_dwg || !region->is_private_copy) continue;

                    DEBUG_LOG("【方案1】renameat时强制写回私有副本: addr=%p, 长度=%zu",
                              region->addr, region->length);

                    // 写回期间避免被提前解除映射
                    bool prev_preserve = region->should_preserve;
                    region->should_preserve = true;

                    if (create_encrypted_backup(region) == 0) {
                        if (write_encrypted_backup_to_file(newpath,
                                                          region->encrypted_backup,
                                                          region->backup_size) == 0) {
                            DEBUG_LOG("renameat时私有副本写回成功: %s", newpath);
                            region->has_modifications = false;

                            if (region->file_path) free(region->file_path);
                            region->file_path = strdup(newpath);
                        } else {
                            DEBUG_LOG("renameat时私有副本写回失败: %s", newpath);
                        }
                    }

                    // 恢复 preserve 标志
                    region->should_preserve = prev_preserve;
                }
                pthread_mutex_unlock(&mmap_table_mutex);
            } else {
                // 【方案1】仅保留私有副本，延迟到 fsync/close 再处理
                pthread_mutex_lock(&mmap_table_mutex);
                for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
                    mmap_region_t *region = &mmap_regions[i];
                    if (region->addr && region->is_target_dwg && region->is_private_copy) {
                        region->should_preserve = true;
                        if (region->file_path) free(region->file_path);
                        region->file_path = strdup(newpath);
                        DEBUG_LOG("【方案1】标记私有副本延迟处理（at版本）: addr=%p, 新路径=%s", region->addr, newpath);
                    }
                }
                pthread_mutex_unlock(&mmap_table_mutex);
            }

            // 在rename完成后对目标文件做整文件加密（兜底保护）
            if (encrypt_entire_file_inplace(newpath) == 0) {
                DEBUG_LOG("renameat后整文件加密替换完成: %s", newpath);
            } else {
                DEBUG_LOG("renameat后整文件加密替换失败: %s", newpath);
            }
        }
    }

    return result;
}

// ==================== 库初始化与清理 ====================
__attribute__((constructor))
static void dwg_hook_initialize(void) {
    // 清空并初始化日志文件
    if (is_debug_enabled()) {
        FILE *log_file = fopen("/tmp/dwg_hook.log", "w");
        if (log_file) {
            fprintf(log_file, "DWG加密Hook库初始化开始\n");
            fclose(log_file);
        }
    }
    
    DEBUG_LOG("=============================================");
    DEBUG_LOG("DWG文件透明加解密Hook库 - 双方案修复版本");
    DEBUG_LOG("【方案1】整文件替换加密: %s", ENABLE_FINAL_FILE_ENCRYPTION ? "已启用" : "已禁用");
    DEBUG_LOG("【方案2】在线加密（临时文件写入时直接加密）: %s", ENABLE_INLINE_ENCRYPTION ? "已启用" : "已禁用");
    DEBUG_LOG("【整合方案】两套方案协同工作，确保无明文落盘");
    DEBUG_LOG("【内存同步】保存后自动同步内存映射区域状态");
    DEBUG_LOG("功能: 进程内明文编辑，磁盘保持密文状态");
    DEBUG_LOG("双保险机制: 方案1(整文件替换) + 方案2(在线加密)");
    DEBUG_LOG("调试模式: %s", is_debug_enabled() ? "已启用" : "已禁用");
    DEBUG_LOG("mmap私有副本机制: 已启用 (MAP_SHARED->MAP_PRIVATE)");
    DEBUG_LOG("编译时间: %s %s", __DATE__, __TIME__);
    DEBUG_LOG("方案1-整文件加密: %s", ENABLE_FINAL_FILE_ENCRYPTION ? "已启用" : "已禁用");
    DEBUG_LOG("方案2-在线加密: %s", ENABLE_INLINE_ENCRYPTION ? "已启用" : "已禁用");
    DEBUG_LOG("=============================================");
}

__attribute__((destructor))
static void dwg_hook_cleanup(void) {
    DEBUG_LOG("DWG Hook库清理开始...");
    
    // 在库卸载前写回所有未保存的私有副本
    pthread_mutex_lock(&mmap_table_mutex);
    int cleanup_count = 0;
    
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        mmap_region_t *region = &mmap_regions[i];
        if (!region->addr) continue;
        
        if (region->is_target_dwg && region->is_private_copy && region->file_path) {
            DEBUG_LOG("清理时写回私有副本: 地址=%p, 长度=%zu, 路径=%s", 
                     region->addr, region->length, region->file_path);
            
            BEGIN_INTERNAL_IO();
            if (create_encrypted_backup(region) == 0) {
                if (write_encrypted_backup_to_file(region->file_path, 
                                                  region->encrypted_backup, 
                                                  region->backup_size) == 0) {
                    cleanup_count++;
                    DEBUG_LOG("清理写回成功");
                } else {
                    DEBUG_LOG("清理写回失败");
                }
            }
            END_INTERNAL_IO();
            
            // 清理完成后，强制解除映射
            if (region->addr) {
                static int (*real_munmap)(void *, size_t) = NULL;
                if (!real_munmap) real_munmap = dlsym(RTLD_NEXT, "munmap");
                real_munmap(region->addr, region->length);
            }
        }
        
        // 清理资源
        if (region->encrypted_backup) {
            free(region->encrypted_backup);
        }
        if (region->file_path) {
            free(region->file_path);
        }
    }
    
    pthread_mutex_unlock(&mmap_table_mutex);
    
    DEBUG_LOG("DWG Hook库清理完成，共处理%d个私有副本", cleanup_count);
    DEBUG_LOG("=============================================");
}