// /home/chane/tif_crypto_hook/tif_interceptor.c
// 编译共享库命令：gcc -shared -fPIC -o /home/chane/tif_crypto_hook/libtif_interceptor.so /home/chane/tif_crypto_hook/tif_interceptor.c -ldl
// gcc -Wall -fPIC -shared -o libtif_interceptor.so tif_interceptor.c -ldl
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>
#include <errno.h>

// 原始企业文件头（未加密）
static unsigned char ORIGINAL_HEADER[4096] = {
    0xFF, 0xF7, 0xF0, 0x7F, 0x77, 0x70, 0x0F, 0x07, 0x07, 0x0F, 0x70, 0x77, 0x7F, 0xF0, 0xF7, 0xFF,
    0xC4, 0xCF, 0xBE, 0xA9, 0xBC, 0xAA, 0xD3, 0xA1, 0xD0, 0xC5, 0xCF, 0xA2, 0xBF, 0xC6, 0xBC, 0xBC,
    0xD3, 0xD0, 0xCF, 0xDE, 0xB9, 0xAB, 0xCB, 0xBE, 0xBC, 0xD3, 0xC3, 0xDC, 0xCE, 0xC4, 0xBC, 0xFE
    // 填充剩余部分为 0xFF
    // 实际应根据您的企业文件头填充完整 4096 字节
};

// 初始化填充文件头
__attribute__((constructor)) void init_header() {
    // 确保头部完整为 4096 字节
    for (int i = 48; i < sizeof(ORIGINAL_HEADER); i++) {
        ((unsigned char*)ORIGINAL_HEADER)[i] = 0xFF;
    }
}

// 解密函数（仅用于数据部分）
void xor_decrypt(char *buf, size_t size) {
    if (!buf) return; //解密前添加 NULL 和越界检查
    for (size_t i = 0; i < size; i++) {
        buf[i] ^= 0xFF;
    }
}

// 检查是否为加密的TIF文件
int is_encrypted_tif(const char *path) {
    if (!path) return 0;
    
    // 检查是否在目标目录
    const char *target_dir = "/home/chane/tif_crypto_hook/1-6级tif文件";
    if (strstr(path, target_dir) == NULL) return 0;
    
    // 检查文件名前缀
    const char *basename = strrchr(path, '/');
    if (!basename) basename = path;
    else basename++;
    
    return (strncmp(basename, "changed_", 8) == 0) && 
           (strcasestr(basename, ".tif") || strcasestr(basename, ".tiff"));
}

// 记录自定义分配的内存映射
struct mmap_record {
    void *orig_addr;      // 原始 mmap 地址
    void *custom_addr;    // 自定义分配地址
    size_t length;        // 映射长度
    int fd;               // 文件描述符
    off_t offset;         // 文件偏移
    struct mmap_record *next;
};

static struct mmap_record *mmap_list = NULL;
static pthread_mutex_t mmap_mutex = PTHREAD_MUTEX_INITIALIZER;

// 添加映射记录
void add_mmap_record(void *orig_addr, void *custom_addr, size_t length, int fd, off_t offset) {
    struct mmap_record *record = malloc(sizeof(struct mmap_record));
    if (!record) return;
    
    record->orig_addr = orig_addr;
    record->custom_addr = custom_addr;
    record->length = length;
    record->fd = fd;
    record->offset = offset;
    
    pthread_mutex_lock(&mmap_mutex);
    record->next = mmap_list;
    mmap_list = record;
    pthread_mutex_unlock(&mmap_mutex);
}

// 查找映射记录
struct mmap_record *find_mmap_record(void *addr) {
    pthread_mutex_lock(&mmap_mutex);
    struct mmap_record *current = mmap_list;
    
    while (current) {
        // 检查地址是否在范围内
        if (addr >= current->custom_addr && 
            (char*)addr < (char*)current->custom_addr + current->length) {
            pthread_mutex_unlock(&mmap_mutex);
            return current;
        }
        current = current->next;
    }
    
    pthread_mutex_unlock(&mmap_mutex);
    return NULL;
}

// 移除映射记录
void remove_mmap_record(void *addr) {
    pthread_mutex_lock(&mmap_mutex);
    struct mmap_record **current = &mmap_list;
    
    while (*current) {
        if ((*current)->custom_addr == addr) {
            struct mmap_record *to_free = *current;
            *current = (*current)->next;
            free(to_free);
            pthread_mutex_unlock(&mmap_mutex);
            return;
        }
        current = &(*current)->next;
    }
    
    pthread_mutex_unlock(&mmap_mutex);
}

// 增强版 mmap 拦截
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    static void *(*real_mmap)(void*, size_t, int, int, int, off_t) = NULL;
    /* **************** 修改过 ***************************** */
    // if (!real_mmap) real_mmap = dlsym(RTLD_NEXT, "mmap");
    char actual_path[1024] = {0};
    if (!real_mmap) {
        real_mmap = dlsym(RTLD_NEXT, "mmap");
        if (!real_mmap) {

            /* **************** 修改过 ***************************** */
            // fprintf(stderr, "[HOOK] dlsym(mmap) 失败: %s\n", dlerror());
            fprintf(stderr, "[HOOK] mmap: file=%s offset=%ld length=%zu\n", actual_path, offset, length);
            /* **************** 修改分界线 ***************************** */

            exit(1);  // 防止继续运行导致段错误
        }
    }
    /* **************** 分界线 ***************************** */

    // 首先检查是否为加密 TIF 文件
    int is_target_file = 0;
    // char actual_path[1024] = {0};
    
    if (fd >= 0) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
        ssize_t len = readlink(path, actual_path, sizeof(actual_path)-1);
        if (len > 0) {
            actual_path[len] = '\0';
            is_target_file = is_encrypted_tif(actual_path);
        }
    }
    
    // 非目标文件或无效文件，直接返回
    if (!is_target_file) {
        return real_mmap(addr, length, prot, flags, fd, offset);
    }
    
    // 获取文件大小
    struct stat st;
    if (fstat(fd, &st) == -1) {
        return real_mmap(addr, length, prot, flags, fd, offset);
    }
    size_t file_size = st.st_size;
    
    // 计算实际需要映射的范围
    off_t map_start = offset;
    size_t map_length = length;
    
    // 确保不超出文件范围
    if (map_start + map_length > file_size) {
        map_length = file_size - map_start;
    }
    
    // 使用原始 mmap 映射文件内容
    void *orig_mapped = real_mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (orig_mapped == MAP_FAILED) {
        return MAP_FAILED;
    }
    
    // 分配自定义内存区域
    void *custom_mapped = malloc(map_length);
    if (!custom_mapped) {
        munmap(orig_mapped, file_size);
        errno = ENOMEM;
        return MAP_FAILED;
    }
    
    // 复制请求的数据范围
    char *src_start = (char*)orig_mapped + map_start;
    memcpy(custom_mapped, src_start, map_length);
    
    // === 关键修改：处理文件头和数据部分 ===
    
    // 1. 替换文件头部分为原始企业文件头
    if (map_start < sizeof(ORIGINAL_HEADER)) {
        size_t header_copy_start = map_start;
        size_t header_copy_end = map_start + map_length;
        if (header_copy_end > sizeof(ORIGINAL_HEADER)) {
            header_copy_end = sizeof(ORIGINAL_HEADER);
        }
        
        size_t header_copy_size = header_copy_end - header_copy_start;
        
        // 替换自定义内存中的文件头部分
        memcpy(custom_mapped, 
               ORIGINAL_HEADER + header_copy_start, 
               header_copy_size);
    }
    
    // 2. 解密数据部分（4096字节之后）
    if (map_start + map_length > 4096) {
        // 计算数据部分的起始位置和大小
        off_t data_offset_in_file = (map_start < 4096) ? 4096 : map_start;
        size_t data_offset_in_mem = (map_start < 4096) ? (4096 - map_start) : 0;
        size_t data_size = map_length - data_offset_in_mem;
        
        if (data_size > 0) {
            // 解密数据部分
            xor_decrypt((char*)custom_mapped + data_offset_in_mem, data_size);
        }
    }
    
    // 清理原始映射
    munmap(orig_mapped, file_size);
    
    // 记录映射信息
    add_mmap_record(orig_mapped, custom_mapped, map_length, fd, offset);
    
    return custom_mapped;
}

// 拦截 munmap
int munmap(void *addr, size_t length) {
    static int (*real_munmap)(void*, size_t) = NULL;
    if (!real_munmap) real_munmap = dlsym(RTLD_NEXT, "munmap");
    
    // 检查是否为自定义映射
    struct mmap_record *record = find_mmap_record(addr);
    if (record) {
        // 释放自定义内存
        free(record->custom_addr);
        remove_mmap_record(addr);
        return 0; // 成功
    }
    
    // 普通映射
    return real_munmap(addr, length);
}

// 拦截 madvise
int madvise(void *addr, size_t length, int advice) {
    static int (*real_madvise)(void*, size_t, int) = NULL;
    if (!real_madvise) real_madvise = dlsym(RTLD_NEXT, "madvise");
    
    // 如果是自定义映射，忽略建议
    if (find_mmap_record(addr)) {
        return 0; // 成功
    }
    
    return real_madvise(addr, length, advice);
}

// 拦截其他文件读取函数
ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real_read)(int, void*, size_t) = NULL;
    if (!real_read) real_read = dlsym(RTLD_NEXT, "read");
    
    ssize_t result = real_read(fd, buf, count);
    
    // 如果是加密的TIF文件，进行解密
    if (result > 0) {
        char path[1024];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
        
        char actual_path[1024];
        ssize_t len = readlink(path, actual_path, sizeof(actual_path)-1);
        if (len > 0) {
            actual_path[len] = '\0';
            if (is_encrypted_tif(actual_path)) {
                off_t current_pos = lseek(fd, 0, SEEK_CUR);
                off_t read_start = current_pos - result;
                
                // 只解密数据部分（跳过4096字节的文件头）
                if (read_start + result > 4096) {
                    size_t decrypt_start = (read_start < 4096) ? (4096 - read_start) : 0;
                    size_t decrypt_size = result - decrypt_start;
                    
                    if (decrypt_size > 0) {
                        xor_decrypt((char*)buf + decrypt_start, decrypt_size);
                    }
                }
            }
        }
    }
    
    return result;
}