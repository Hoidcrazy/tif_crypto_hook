// 文件路径: /home/chane/tif_crypto_hook/dwg_hook.c

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


// ==================== 配置与全局变量 ====================

// 定义最大可跟踪的文件描述符数量
// Linux 默认每个进程最多 1024 个 fd，此值足够覆盖常见情况
#define MAX_TRACKED_FD 1024

// 全局数组：存储文件描述符 (fd) 到文件路径字符串的映射
// fd_paths[fd] = "/path/to/file.dwg" 或 NULL
// 使用指针数组是因为路径长度可变，需要动态分配内存
static char *fd_paths[MAX_TRACKED_FD] = {0}; // 初始化为全 NULL

// 互斥锁：保护 fd_paths 数组的读写操作
// 防止多线程环境下同时修改导致数据竞争和内存错误
static pthread_mutex_t fd_mutex = PTHREAD_MUTEX_INITIALIZER;

// 调试标志：控制是否输出调试日志
// -1: 未初始化; 0: 关闭; 1: 开启
// 使用环境变量 DWG_HOOK_DEBUG 控制，便于线上关闭
static int debug_enabled = -1;

// ==================== 调试函数 ====================

/**
 * 初始化调试标志
 * 从环境变量 DWG_HOOK_DEBUG 读取配置，只执行一次
 * 这是一个惰性初始化函数，在首次需要日志时才检查环境变量
 */
void init_debug_flag() {
    if (debug_enabled == -1) { // 仅初始化一次
        const char *env = getenv("DWG_HOOK_DEBUG"); // 获取环境变量
        debug_enabled = (env && strcmp(env, "1") == 0) ? 1 : 0; // 只有值为 "1" 时开启
    }
}

/**
 * 调试日志输出宏
 * 使用方式: DEBUG_LOG("fd=%d, path=%s", fd, path);
 * 特性:
 *   - 自动包含 "[DWG_HOOK] " 前缀便于识别
 *   - 通过 init_debug_flag() 控制是否输出
 *   - 输出到 stderr，可被重定向
 *   - 使用 do-while(0) 包装确保语法正确性
 */
#define DEBUG_LOG(fmt, ...) \
    do { \
        init_debug_flag(); \
        if (debug_enabled) { \
            FILE *logfp = fopen("/tmp/dwg_hook.log", "a"); \
            if (logfp) { \
                fprintf(logfp, "[DWG_HOOK] " fmt "\n", ##__VA_ARGS__); \
                fclose(logfp); \
            } \
        } \
    } while (0)

// ==================== 工具函数 ====================

/**
 * 判断给定路径是否为需要解密的目标 DWG 文件
 *
 * 匹配条件（两个条件必须同时满足）:
 *   1. 路径中包含子字符串 "changed_"
 *   2. 路径以 ".dwg" 结尾（不区分大小写，如 .DWG, .Dwg 也匹配）
 *
 * @param path: 待检查的文件路径字符串，可为 NULL
 * @return: 1 表示是目标文件需要解密，0 表示不是
 */
int is_target_dwg_file(const char *path) {
    if (!path) {
        // 如果路径为空，记录错误信息并返回
        DEBUG_LOG("Path is NULL.");
        return 0;
    }

    // 记录正在检查的文件路径
    DEBUG_LOG("Checking file path: %s", path);

    size_t len = strlen(path);
    // 检查路径长度是否至少为 4 字符（".dwg" 长度）
    if (len < 4) {
        DEBUG_LOG("File path too short: %s", path);
        return 0;
    }
    
    // 获取路径末尾4个字符的指针
    const char *ext = path + len - 4;
    // 不区分大小写比较扩展名
    if (strcasecmp(ext, ".dwg") != 0) {
        DEBUG_LOG("File does not end with .dwg: %s", path);
        return 0;
    }

    // 检查路径中是否包含 "changed_" 子串
    if (strstr(path, "changed_") == NULL) {
        DEBUG_LOG("File does not contain 'changed_': %s", path);
        return 0;
    }

    // 如果所有条件都满足，记录该文件被识别为目标文件
    DEBUG_LOG("Target DWG file detected: %s", path);
    return 1;
}

/**
 * 记录文件描述符与文件路径的映射关系
 * 在 open/openat 成功后调用，建立 fd -> path 的关联
 * 
 * 此函数是线程安全的，内部使用互斥锁保护
 * 
 * @param fd: 成功打开的文件描述符
 * @param path: 对应的文件路径（原始传入的路径）
 */
static void track_fd(int fd, const char *path) {
    // 参数合法性检查
    if (fd < 0 || fd >= MAX_TRACKED_FD || !path) return;

    // 加锁，保护共享资源 fd_paths
    pthread_mutex_lock(&fd_mutex);

    // 释放该 fd 之前可能存在的路径内存（防止内存泄漏）
    free(fd_paths[fd]);
    fd_paths[fd] = NULL;

    // 尝试获取绝对路径，解决相对路径（如 ./file.dwg）和符号链接问题
    char *resolved = realpath(path, NULL);
    if (resolved) {
        fd_paths[fd] = resolved; // 使用解析后的绝对路径
    } else {
        // realpath 失败（常见于文件已删除但 fd 仍有效），使用原始路径副本
        fd_paths[fd] = strdup(path);
        // 注意：strdup 可能因内存不足返回 NULL，此时 fd_paths[fd] 为 NULL
        //      在读取时会通过 /proc/self/fd 回退机制获取路径
    }

    // 解锁
    pthread_mutex_unlock(&fd_mutex);
}

/**
 * 获取指定文件描述符对应的文件路径
 * 提供统一的路径获取接口，优先使用已记录的路径，其次尝试 /proc/self/fd
 * 
 * @param fd: 文件描述符
 * @param buf: 临时缓冲区，用于存储通过 readlink 获取的路径
 * @param bufsize: buf 的大小
 * @return: 指向路径字符串的指针，失败时返回 NULL
 * 
 * 调用者应确保 buf 足够大（建议 PATH_MAX）
 */
static const char *get_fd_path(int fd, char *buf, size_t bufsize) {
    const char *path = NULL;

    // 1. 优先从 fd_paths 映射表中查找（由 open/openat 建立）
    pthread_mutex_lock(&fd_mutex);
    path = fd_paths[fd];
    pthread_mutex_unlock(&fd_mutex);

    if (path) return path; // 找到则直接返回

    // 2. 映射表中无记录，尝试通过 /proc/self/fd/<fd> 获取
    //    这是 Linux 特有的机制，可获取任何有效 fd 指向的文件
    snprintf(buf, bufsize, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(buf, buf, bufsize - 1); // readlink 不添加 null 终止符
    if (n != -1) {
        buf[n] = '\0'; // 手动添加字符串结束符
        return buf;    // 返回指向 buf 的指针
    }

    // 3. 所有方法均失败
    return NULL;
}

// ==================== mmap / mmap64 跟踪结构 ====================

// 用于记录 mmap 映射信息：地址范围 + 是否需要解密
typedef struct {
    void *addr;
    size_t length;
    int should_decrypt;
} mmap_region_t;

// 最大跟踪的 mmap 区域数量（可根据需要调整）
#define MAX_MMAP_REGIONS 256
static mmap_region_t mmap_regions[MAX_MMAP_REGIONS] = {0};
static pthread_mutex_t mmap_mutex = PTHREAD_MUTEX_INITIALIZER;

// 尝试将指定内存区域标记为需解密（仅当属于目标文件时）
static void track_mmap_region(void *addr, size_t length, int should_decrypt) {
    if (!addr || length == 0 || !should_decrypt) return;

    pthread_mutex_lock(&mmap_mutex);

    // 查找空槽
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == NULL) {
            mmap_regions[i].addr = addr;
            mmap_regions[i].length = length;
            mmap_regions[i].should_decrypt = should_decrypt;
            DEBUG_LOG("[MMAP] Tracked region: addr=%p, len=%zu, decrypt=1", addr, length);
            break;
        }
    }

    pthread_mutex_unlock(&mmap_mutex);
}

// 查询某地址是否在需解密的 mmap 区域内
static int is_mmap_region_need_decrypt(void *addr, size_t len) {
    if (!addr || len == 0) return 0;

    pthread_mutex_lock(&mmap_mutex);
    int result = 0;
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == NULL) continue;

        void *reg_start = mmap_regions[i].addr;
        void *reg_end = (char*)mmap_regions[i].addr + mmap_regions[i].length;
        void *req_start = addr;
        void *req_end = (char*)addr + len;

        // 检查是否有重叠
        if (req_start < reg_end && req_end > reg_start) {
            if (mmap_regions[i].should_decrypt) {
                result = 1;
                break;
            }
        }
    }
    pthread_mutex_unlock(&mmap_mutex);

    return result;
}

// 安全地对 mmap 映射的内存区域执行异或解密
// 返回值：0 = 成功，-1 = 失败（如 mprotect 失败）
static int safe_decrypt_mmap_region(void *addr, size_t length) {
    if (!addr || length == 0) {
        DEBUG_LOG("[MMAP_DECRYPT] Invalid address or length: addr=%p, len=%zu", addr, length);
        return -1;
    }

    // 1. 临时修改内存权限为可读写
    if (mprotect(addr, length, PROT_READ | PROT_WRITE) != 0) {
        DEBUG_LOG("[MMAP_DECRYPT] mprotect failed: addr=%p, len=%zu, errno=%d (%s)",
                  addr, length, errno, strerror(errno));
        return -1; // 权限修改失败，无法解密
    }

    DEBUG_LOG("[MMAP_DECRYPT] mprotect OK: %p+%zu now RW", addr, length);

    // 2. 执行异或解密
    unsigned char *data = (unsigned char *)addr;
    for (size_t i = 0; i < length; ++i) {
        data[i] ^= 0xFF;
    }

    DEBUG_LOG("[MMAP_DECRYPT] Decryption completed: %p+%zu (first bytes: %02x %02x %02x ...)",
              addr, length, data[0], data[1], data[2]);

    // 3. 恢复原始保护属性（假设原始为 PROT_READ）
    // 注意：实际原始 prot 需从 /proc/self/maps 读取，此处简化为恢复只读
    if (mprotect(addr, length, PROT_READ) != 0) {
        DEBUG_LOG("[MMAP_DECRYPT] mprotect restore failed: addr=%p, len=%zu, errno=%d (%s)",
                  addr, length, errno, strerror(errno));
        // 即使失败也不应让程序崩溃，记录日志即可
    } else {
        DEBUG_LOG("[MMAP_DECRYPT] mprotect restored: %p+%zu -> PROT_READ", addr, length);
    }

    return 0; // 成功
}

// 清理 mmap 区域（在 munmap 时调用）
static void untrack_mmap_region(void *addr) {
    pthread_mutex_lock(&mmap_mutex);
    for (int i = 0; i < MAX_MMAP_REGIONS; i++) {
        if (mmap_regions[i].addr == addr) {
            DEBUG_LOG("[MMAP] Untracked region: addr=%p, len=%zu", addr, mmap_regions[i].length);
            mmap_regions[i].addr = NULL;
            mmap_regions[i].length = 0;
            mmap_regions[i].should_decrypt = 0;
            break;
        }
    }
    pthread_mutex_unlock(&mmap_mutex);
}


// ==================== Hook 函数实现 ====================

/**
 * 拦截 openat 系统调用
 * 功能:
 *   - 调用原始 openat 打开文件
 *   - 记录成功打开的 fd 与路径的映射关系
 *   - 返回原始 openat 的返回值
 * 
 * 特别处理:
 *   - 正确处理可变参数（特别是 O_CREAT 时的 mode 参数）
 *   - 使用 dlsym(RTLD_NEXT) 获取下一个定义的 openat（即 libc 的实现）
 */
int openat(int dirfd, const char *pathname, int flags, ...) {
    static int (*real_openat)(int, const char *, int, ...) = NULL;
    if (!real_openat)
        real_openat = dlsym(RTLD_NEXT, "openat");

    // 处理可变参数：只有 flags 包含 O_CREAT 时才需要 mode 参数
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int); // 获取 mode 参数
        va_end(args);
    }

    DEBUG_LOG("openat: dirfd=%d, pathname='%s', flags=0x%x%s, mode=0%o",
        dirfd, pathname ? pathname : "(null)",
        flags,
        (flags & O_CREAT) ? " | O_CREAT" : "",
        mode);

    // 调用真实的 openat 系统调用
    int fd;
    if (flags & O_CREAT) {
        fd = real_openat(dirfd, pathname, flags, mode);
    } else {
        fd = real_openat(dirfd, pathname, flags);
    }

    // 如果文件成功打开，记录 fd -> path 映射
    if (fd >= 0) {
        // 记录 fd -> path 映射
        track_fd(fd, pathname);

        // 检查是否是目标 DWG 文件
        if (is_target_dwg_file(pathname)) {
            DEBUG_LOG("[TRACKED] openat: fd=%d -> '%s' (TARGET DWG)", fd, pathname);
        } else {
            DEBUG_LOG("openat: fd=%d -> '%s' (not a target)", fd, pathname);
        }
    } else {
        DEBUG_LOG("openat 失败: dirfd=%d, path='%s', errno=%d (%s)",
                  dirfd, pathname ? pathname : "(null)", errno, strerror(errno));
    }

    return fd;
}

/**
 * 拦截 open 系统调用
 * 功能与 openat 相同，用于兼容只使用 open 的程序
 * 实现方式几乎完全相同，只是函数签名不同
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

    DEBUG_LOG("open: pathname='%s', flags=0x%x%s, mode=0%o",
        pathname ? pathname : "(null)",
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
            DEBUG_LOG("[TRACKED] open: fd=%d -> '%s' (TARGET DWG)", fd, pathname);
        } else {
            DEBUG_LOG("open: fd=%d -> '%s' (not a target)", fd, pathname);
        }
    } else {
        DEBUG_LOG("open 失败: path='%s', errno=%d (%s)",
                  pathname ? pathname : "(null)", errno, strerror(errno));
    }

    return fd;
}

/**
 * 核心函数：拦截 pread64 系统调用
 * 功能:
 *   - 调用原始 pread64 从文件指定偏移读取数据
 *   - 检查该 fd 对应的文件是否为需要解密的目标文件
 *   - 如果是，则对读取到的缓冲区数据进行 0xFF 异或解密
 *   - 返回原始 pread64 的返回值
 * 
 * 为什么用 pread64:
 *   - 中望CAD通过 strace 确认为 pread64 读取 DWG 文件
 *   - pread64 可指定偏移，无需移动文件指针，适合随机访问
 */
ssize_t pread64(int fd, void *buf, size_t count, off_t offset) {
    static ssize_t (*real_pread64)(int, void *, size_t, off_t) = NULL;
    if (!real_pread64)
        real_pread64 = dlsym(RTLD_NEXT, "pread64");

    // 调用真实的 pread64 读取数据
    ssize_t ret = real_pread64(fd, buf, count, offset);

    // 错误或无效返回值检查
    if (ret <= 0 || fd < 0 || fd >= MAX_TRACKED_FD) {
        DEBUG_LOG("pread64 failed or invalid fd: fd=%d, ret=%zd", fd, ret);
        return ret;
    }

    // 获取该 fd 对应的文件路径
    char path_buf[PATH_MAX]; // 临时缓冲区
    const char *path = get_fd_path(fd, path_buf, sizeof(path_buf));

    // 输出调试日志（如果开启）
    DEBUG_LOG("pread64(fd=%d, offset=%ld, count=%zu, ret=%zd, path=%s)%s",
              fd, (long)offset, count, ret,
              path ? path : "(unknown)",
              is_target_dwg_file(path) ? " [DECRYPTED]" : "");

    // 如果是目标加密文件，执行解密
    if (is_target_dwg_file(path)) {
        DEBUG_LOG("Decryption required for file: %s", path);
        unsigned char *data = (unsigned char *)buf;

        // 打印解密前的数据
        DEBUG_LOG("解密前: 缓冲区前3字节: %02x %02x %02x ...",
            data[0], data[1], data[2]);

        for (ssize_t i = 0; i < ret; ++i) {
            data[i] ^= 0xFF; // 0xFF 异或：加密和解密是同一操作
        }

        // 打印解密后的数据
        DEBUG_LOG("解密后: 缓冲区前3字节: %02x %02x %02x ...",
            data[0], data[1], data[2]);

        DEBUG_LOG("Decryption completed for file: %s", path);
    }else {
        DEBUG_LOG("No decryption needed for file: %s", path);
    }

    return ret;
}

/**
 * 拦截 read 系统调用
 * 实现逻辑与 pread64 完全相同，只是函数名和参数不同
 */
ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real_read)(int, void *, size_t) = NULL;
    if (!real_read)
        real_read = dlsym(RTLD_NEXT, "read");

    ssize_t ret = real_read(fd, buf, count);
    if (ret <= 0 || fd < 0 || fd >= MAX_TRACKED_FD){
        DEBUG_LOG("read failed or invalid fd: fd=%d, ret=%zd", fd, ret);
        return ret;
    }

    char path_buf[PATH_MAX];
    const char *path = get_fd_path(fd, path_buf, sizeof(path_buf));

    DEBUG_LOG("read(fd=%d, count=%zu, ret=%zd, path=%s)%s",
              fd, count, ret,
              path ? path : "(unknown)",
              is_target_dwg_file(path) ? " [DECRYPTED]" : "");

    if (is_target_dwg_file(path)) {
        DEBUG_LOG("Decryption required for file: %s", path);
        unsigned char *data = (unsigned char *)buf;

        // 打印解密前的数据
        DEBUG_LOG("解密前: 缓冲区前3字节: %02x %02x %02x ...",
            data[0], data[1], data[2]);
        
        for (ssize_t i = 0; i < ret; ++i) {
            data[i] ^= 0xFF;
        }

        // 打印解密后的数据
        DEBUG_LOG("解密后: 缓冲区前3字节: %02x %02x %02x ...",
            data[0], data[1], data[2]);

        DEBUG_LOG("Decryption completed for file: %s", path);
    }else {
        DEBUG_LOG("No decryption needed for file: %s", path);
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

    DEBUG_LOG("mmap: addr=%p, len=%zu, prot=0x%x, flags=0x%x, fd=%d, offset=%ld, path=%s",
              addr, length, prot, flags, fd, (long)offset, path ? path : "(no fd)");

    void *ptr = real_mmap(addr, length, prot, flags, fd, offset);
    if (ptr == MAP_FAILED) {
        DEBUG_LOG("mmap FAILED: errno=%d (%s)", errno, strerror(errno));
        return ptr;
    }

    int should_decrypt = 0;
    if (fd >= 0 && path && is_target_dwg_file(path)) {
        should_decrypt = 1;
        DEBUG_LOG("[MMAP] Target file mapped: fd=%d, path=%s, region=%p+%zu", fd, path, ptr, length);
    } else {
        DEBUG_LOG("mmap: No decryption needed for this mapping (fd=%d)", fd);
    }

    // ====== 安全解密逻辑 ======
    if (should_decrypt) {
        if (safe_decrypt_mmap_region(ptr, length) == 0) {
            DEBUG_LOG("[MMAP_DECRYPT] Successfully decrypted mapped region: %p+%zu", ptr, length);
        } else {
            DEBUG_LOG("[MMAP_DECRYPT] Failed to decrypt mapped region: %p+%zu", ptr, length);
        }
    }

    // 仍记录 region（可用于后续验证或调试）
    track_mmap_region(ptr, length, should_decrypt);

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

    DEBUG_LOG("mmap64: addr=%p, len=%zu, prot=0x%x, flags=0x%x, fd=%d, offset=%lld, path=%s",
              addr, length, prot, flags, fd, (long long)offset, path ? path : "(no fd)");

    void *ptr = real_mmap64(addr, length, prot, flags, fd, offset);
    if (ptr == MAP_FAILED) {
        DEBUG_LOG("mmap64 FAILED: errno=%d (%s)", errno, strerror(errno));
        return ptr;
    }

    int should_decrypt = 0;
    if (fd >= 0 && path && is_target_dwg_file(path)) {
        should_decrypt = 1;
        DEBUG_LOG("[MMAP64] Target file mapped: fd=%d, path=%s, region=%p+%zu", fd, path, ptr, length);
    } else {
        DEBUG_LOG("mmap64: No decryption needed for this mapping (fd=%d)", fd);
    }

    // ====== 安全解密逻辑 ======
    if (should_decrypt) {
        if (safe_decrypt_mmap_region(ptr, length) == 0) {
            DEBUG_LOG("[MMAP_DECRYPT] Successfully decrypted mapped region (mmap64): %p+%zu", ptr, length);
        } else {
            DEBUG_LOG("[MMAP_DECRYPT] Failed to decrypt mapped region (mmap64): %p+%zu", ptr, length);
        }
    }

    track_mmap_region(ptr, length, should_decrypt);

    return ptr;
}

/**
 * munmap Hook：清理 mmap 记录
 */
int munmap(void *addr, size_t length) {
    static int (*real_munmap)(void *, size_t) = NULL;
    if (!real_munmap)
        real_munmap = dlsym(RTLD_NEXT, "munmap");

    DEBUG_LOG("munmap: addr=%p, len=%zu", addr, length);

    int ret = real_munmap(addr, length);
    if (ret == 0) {
        DEBUG_LOG("munmap: successfully unmapped %p+%zu", addr, length);
        // 清理 mmap 跟踪记录
        untrack_mmap_region(addr);
    } else {
        DEBUG_LOG("munmap FAILED: addr=%p, errno=%d (%s)", addr, errno, strerror(errno));
    }

    return ret;
}


/**
 * 拦截 close 系统调用
 * 功能:
 *   - 调用原始 close 关闭文件
 *   - 清理 fd_paths 中对应的路径记录，释放内存
 *   - 防止内存泄漏
 */
int close(int fd) {
    static int (*real_close)(int) = NULL;
    if (!real_close)
        real_close = dlsym(RTLD_NEXT, "close");

    // 用于日志：保存路径副本，避免释放后访问
    char *tracked_path = NULL;

    // 在锁内获取路径，避免竞争
    pthread_mutex_lock(&fd_mutex);
    if (fd >= 0 && fd < MAX_TRACKED_FD && fd_paths[fd] != NULL) {
        tracked_path = strdup(fd_paths[fd]);  // 复制路径字符串
    }
    pthread_mutex_unlock(&fd_mutex);

    DEBUG_LOG("close: fd=%d, path='%s'", fd, tracked_path ? tracked_path : "(null)");

    // 执行真实 close
    int ret = real_close(fd);

    if (ret == 0) {
        DEBUG_LOG("close: fd=%d successfully closed", fd);
        if (tracked_path) {
            DEBUG_LOG("close: cleaned up path='%s'", tracked_path);
        }
    } else {
        DEBUG_LOG("close FAILED: fd=%d, errno=%d (%s)", fd, errno, strerror(errno));
        if (tracked_path) {
            DEBUG_LOG("close: failed to close tracked file='%s'", tracked_path);
        }
    }

    // 真正清理资源（在锁内）
    pthread_mutex_lock(&fd_mutex);
    if (fd >= 0 && fd < MAX_TRACKED_FD) {
        free(fd_paths[fd]);
        fd_paths[fd] = NULL;
    }
    pthread_mutex_unlock(&fd_mutex);

    // 释放日志用的副本
    free(tracked_path);

    return ret;
}
