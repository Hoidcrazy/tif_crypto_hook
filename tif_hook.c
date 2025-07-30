// tif_hook.c
// 功能：通过 LD_PRELOAD 技术，拦截文件读取操作（read/fread/mmap），对特定加密的 TIFF 文件进行透明解密（XOR 0xFF）
// 用途：使应用程序（如麒麟图片查看器）能够正常打开被简单加密的 TIFF 文件
// LD_PRELOAD=/home/chane/tif_crypto_hook/libtif_hook.so /usr/bin/kylin-photo-viewer "/home/chane/tif_crypto_hook/tif_tests/noheader_changed_Level_2.tif"
// gcc -fPIC -shared -o libtif_hook.so tif_hook.c -ldl

#define _GNU_SOURCE  // 启用 GNU 扩展，允许使用 readlink, dlsym 等非标准函数

#include <stdio.h>     // 标准输入输出（fprintf, perror）
#include <stdlib.h>    // 标准库（malloc, free, exit）
#include <string.h>    // 字符串操作（strstr）
#include <sys/mman.h>  // mmap, mprotect 系统调用
#include <unistd.h>    // readlink, sysconf
#include <fcntl.h>     // open, fcntl
#include <dlfcn.h>     // dlsym, RTLD_NEXT - 用于动态链接库符号解析
#include <stdint.h>    // 固定宽度整数类型（uint8_t）
#include <errno.h>     // 错误码（errno）
#include <sys/types.h> // 基本系统数据类型
#include <sys/stat.h>  // fstat 系统调用
#include <limits.h>    // PATH_MAX 等常量

// =============== 配置参数 ===============
#define XOR_KEY 0xFF           // 解密密钥：使用 XOR 0xFF 进行加解密（即逐字节取反）
#define MAX_LOG_BYTES 8        // 日志中最多显示解密后数据的前 8 个字节，用于调试
// ====================================

// 函数指针，用于保存原始系统调用的真实地址
// 在 Hook 函数中，先通过 dlsym(RTLD_NEXT, "xxx") 获取真实函数，再调用它
static ssize_t (*real_read)(int fd, void *buf, size_t count) = NULL;
static size_t  (*real_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream) = NULL;
static void*   (*real_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset) = NULL;

/**
 * @brief 对缓冲区数据进行 XOR 解密
 * @param buf 要解密的数据缓冲区
 * @param len 缓冲区长度
 * @param key XOR 密钥（本例中为 0xFF）
 * 
 * 注意：XOR 加密/解密是可逆的，加密和解密使用相同函数。
 * 例如：data ^ 0xFF 再次 ^ 0xFF = 原始数据
 */
void xor_decrypt(void *buf, size_t len, uint8_t key) {
    uint8_t *data = (uint8_t *)buf;  // 强制转换为字节指针
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;  // 逐字节 XOR 操作
    }
}

/**
 * @brief 根据文件描述符 (fd) 获取对应的文件路径
 * @param fd 文件描述符
 * @return 成功返回文件路径字符串（静态缓冲区），失败返回 NULL
 * 
 * 实现原理：读取 /proc/self/fd/<fd> 的符号链接目标
 * 例如：/proc/self/fd/3 -> /home/user/file.txt
 */
char* get_file_path_by_fd(int fd) {
    char link_path[64];              // 用于构造 /proc/self/fd/<fd> 路径
    static char file_path[4096];     // 静态缓冲区存储结果（线程不安全，但简单）
    ssize_t len;

    // 构造 proc 文件系统路径
    snprintf(link_path, sizeof(link_path), "/proc/self/fd/%d", fd);
    
    // 读取符号链接指向的实际路径
    len = readlink(link_path, file_path, sizeof(file_path) - 1);
    if (len == -1) {
        return NULL;  // 读取失败（如 fd 无效）
    }
    file_path[len] = '\0';  // 添加字符串结束符
    return file_path;       // 返回静态缓冲区地址（注意：后续调用会覆盖）
}

/**
 * @brief 判断给定路径是否为需要解密的目标文件
 * @param path 文件路径字符串
 * @return 是目标文件返回 1，否则返回 0
 * 
 * 当前规则：路径中包含 "noheader_changed_" 字符串的文件被视为目标文件
 * 可根据需求修改此函数以支持更多匹配规则（如后缀名、正则表达式等）
 */
int is_target_file(const char *path) {
    return path && strstr(path, "noheader_changed_") != NULL;
}

// ==================== Hook 函数实现 ====================

/**
 * @brief Hook 系统调用 read
 * @param fd 文件描述符
 * @param buf 数据缓冲区
 * @param count 要读取的字节数
 * @return 实际读取的字节数，或 -1 表示错误
 * 
 * 功能：拦截 read 调用，在数据读取到用户缓冲区后立即进行解密。
 */
ssize_t read(int fd, void *buf, size_t count) {
    // 首次调用时，通过 dlsym 获取真实的 read 函数地址
    if (!real_read) {
        real_read = dlsym(RTLD_NEXT, "read");
        // 注意：此处未检查 real_read 是否为 NULL，生产环境应添加错误处理
    }

    // 调用真实的 read 函数读取数据
    ssize_t result = real_read(fd, buf, count);
    // 如果读取失败或未读取任何数据，直接返回
    if (result <= 0) return result;

    // 获取该 fd 对应的文件路径
    const char *file_path = get_file_path_by_fd(fd);
    // 如果路径有效且是目标文件，则进行解密
    if (file_path && is_target_file(file_path)) {
        size_t log_bytes = (result > MAX_LOG_BYTES) ? MAX_LOG_BYTES : result;
        
        // 打印调试日志：解密操作的上下文
        fprintf(stderr, "[HOOK] 解密 read(fd=%d, count=%zu) from: %s\n", fd, count, file_path);
        
        // 对已读取的数据进行解密
        xor_decrypt(buf, result, XOR_KEY);
        
        // 打印解密后的前若干字节（十六进制），用于验证解密是否成功
        fprintf(stderr, "[HOOK] 解密后%d字节: ", (int)log_bytes);
        for (int i = 0; i < log_bytes; i++) {
            fprintf(stderr, "%02x ", ((uint8_t*)buf)[i]);
        }
        fprintf(stderr, "\n");
    }
    return result;  // 返回实际读取的字节数
}

/**
 * @brief Hook 标准库函数 fread
 * @param ptr 数据缓冲区
 * @param size 每个元素的大小
 * @param nmemb 元素个数
 * @param stream 文件流指针
 * @return 成功读取的元素个数
 * 
 * 功能：拦截 fread 调用，在数据从文件读入缓冲区后解密。
 * 注意：fread 是基于 FILE* 的高层接口，需通过 fileno() 获取底层 fd。
 */
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (!real_fread) {
        real_fread = dlsym(RTLD_NEXT, "fread");
    }

    // 调用真实的 fread
    size_t result = real_fread(ptr, size, nmemb, stream);
    if (result == 0) return result;  // 读取失败或到达文件末尾

    // 获取 FILE* 对应的文件描述符
    int fd = fileno(stream);
    const char *path = get_file_path_by_fd(fd);
    if (path && is_target_file(path)) {
        size_t total = size * result;  // 计算实际读取的总字节数
        size_t log_bytes = (total > MAX_LOG_BYTES) ? MAX_LOG_BYTES : total;
        
        fprintf(stderr, "[HOOK] 解密 fread(size=%zu*%zu) from: %s\n", size, nmemb, path);
        xor_decrypt(ptr, total, XOR_KEY);
        
        fprintf(stderr, "[HOOK] 解密后%d字节: ", (int)log_bytes);
        for (int i = 0; i < log_bytes; i++) {
            fprintf(stderr, "%02x ", ((uint8_t*)ptr)[i]);
        }
        fprintf(stderr, "\n");
    }
    return result;
}

/**
 * @brief Hook 系统调用 mmap
 * @param addr 建议的映射起始地址
 * @param length 映射区域长度
 * @param prot 内存保护标志（如 PROT_READ, PROT_WRITE）
 * @param flags 映射标志（如 MAP_SHARED, MAP_PRIVATE）
 * @param fd 要映射的文件描述符
 * @param offset 文件映射偏移
 * @return 映射成功返回地址，失败返回 MAP_FAILED
 * 
 * 功能：拦截 mmap 调用，对映射到内存的文件内容进行解密。
 * 特殊处理：需临时修改内存页权限以允许写入（解密操作）。
 */
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    if (!real_mmap) {
        real_mmap = dlsym(RTLD_NEXT, "mmap");
    }

    // 调用真实的 mmap
    void *result = real_mmap(addr, length, prot, flags, fd, offset);
    if (result == MAP_FAILED) return result;  // 映射失败，直接返回

    // 只有当映射区域具有读权限时才可能需要解密
    if (prot & PROT_READ) {
        const char *file_path = get_file_path_by_fd(fd);
        if (file_path && is_target_file(file_path)) {
            struct stat st;
            // 获取文件元信息（主要是文件大小）
            if (fstat(fd, &st) == -1) {
                perror("[HOOK] fstat失败");  // 打印系统错误信息
                return result;
            }

            // 计算实际需要解密的字节数
            // 考虑 offset 可能大于文件大小的情况
            size_t actual_length = 0;
            if (offset < st.st_size) {
                actual_length = st.st_size - offset;  // 从 offset 到文件末尾的长度
                if (actual_length > length) {
                    actual_length = length;  // 不超过请求的映射长度
                }
            }

            if (actual_length > 0) {
                fprintf(stderr, "[HOOK] 解密 mmap(fd=%d, offset=%ld, size=%zu) from: %s\n",
                        fd, offset, actual_length, file_path);

                // 判断是否需要临时提升内存权限（原权限无写权限时）
                int need_protect = !(prot & PROT_WRITE);
                size_t page_size = sysconf(_SC_PAGESIZE);  // 获取系统页面大小（通常 4096）

                uintptr_t start = (uintptr_t)result;                    // 映射区起始地址
                uintptr_t end = start + actual_length;                  // 映射区结束地址
                uintptr_t page_start = start & ~(page_size - 1);        // 向下对齐到页边界
                uintptr_t page_end = (end + page_size - 1) & ~(page_size - 1); // 向上对齐到页边界
                size_t protect_len = page_end - page_start;             // 需要保护的总长度

                // 如果需要写权限但当前没有，则使用 mprotect 临时添加
                if (need_protect && mprotect((void*)page_start, protect_len, prot | PROT_WRITE)) {
                    perror("[HOOK] mprotect添加写权限失败");
                    return result;
                }

                // 执行解密：对映射到内存的文件内容进行 XOR 解密
                xor_decrypt(result, actual_length, XOR_KEY);

                // 恢复原始内存保护权限（如果之前修改过）
                if (need_protect) {
                    mprotect((void*)page_start, protect_len, prot);
                }

                // 打印解密后的前若干字节（十六进制）
                size_t log_bytes = (actual_length > MAX_LOG_BYTES) ? MAX_LOG_BYTES : actual_length;
                fprintf(stderr, "[HOOK] 解密后%d字节: ", (int)log_bytes);
                for (int i = 0; i < log_bytes; i++) {
                    fprintf(stderr, "%02x ", ((uint8_t*)result)[i]);
                }
                fprintf(stderr, "\n");
            }
        }
    }
    return result;  // 返回 mmap 的结果
}

/**
 * @brief 动态库构造函数（Constructor）
 * 在动态库被加载时自动执行（如 LD_PRELOAD 时）
 * 用于初始化 Hook 环境或打印加载日志
 */
__attribute__((constructor))
void so_loaded() {
    fprintf(stderr, "[HOOK] libtif_hook.so 加载成功 (XOR_KEY=0x%02X)\n", XOR_KEY);
}