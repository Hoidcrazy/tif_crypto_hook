// tif_hook_read.c
// 这是一个用于处理加密 TIFF 文件的 read Hook 实现
// 测试命令：LD_PRELOAD=/home/chane/tif_crypto_hook/libtif_hook.so /usr/bin/kylin-photo-viewer "/home/chane/tif_crypto_hook/tif_tests/noheader_changed_Level_2.tif"

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>

#define XOR_KEY 0xFF  // 请根据实际加密方式修改

static ssize_t (*real_read)(int fd, void *buf, size_t count) = NULL;

// 获取文件路径
int get_path_from_fd(int fd, char *buf, size_t size) {
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(link, buf, size - 1);
    if (len == -1) return 0;
    buf[len] = '\0';
    return 1;
}

// 判断是否是目标文件
int is_target_file(const char *path) {
    return strstr(path, "noheader_changed_Level_2.tif") != NULL;
}

// 解密函数
void decrypt_data(char *data, size_t size) {
    fprintf(stderr, "[HOOK] 解密前8字节: %02x %02x %02x %02x %02x %02x %02x %02x\n",
            (unsigned char)data[0], (unsigned char)data[1],
            (unsigned char)data[2], (unsigned char)data[3],
            (unsigned char)data[4], (unsigned char)data[5],
            (unsigned char)data[6], (unsigned char)data[7]);

    for (size_t i = 0; i < size; i++) {
        data[i] ^= XOR_KEY;
    }

    fprintf(stderr, "[HOOK] 解密后8字节: %02x %02x %02x %02x %02x %02x %02x %02x\n",
            (unsigned char)data[0], (unsigned char)data[1],
            (unsigned char)data[2], (unsigned char)data[3],
            (unsigned char)data[4], (unsigned char)data[5],
            (unsigned char)data[6], (unsigned char)data[7]);
}

// read Hook
ssize_t read(int fd, void *buf, size_t count) {
    if (!real_read) {
        real_read = dlsym(RTLD_NEXT, "read");
    }

    char path[512] = {0};
    if (get_path_from_fd(fd, path, sizeof(path)) && is_target_file(path)) {
        fprintf(stderr, "[HOOK] 拦截 read(fd=%d, count=%zu) from file: %s\n", fd, count, path);

        // 先调用真实 read
        ssize_t ret = real_read(fd, buf, count);
        if (ret > 0) {
            // 只解密有效读取的数据
            decrypt_data((char *)buf, ret);
        }

        return ret;
    }

    return real_read(fd, buf, count);
}