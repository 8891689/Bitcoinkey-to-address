/*
 * bech32.c
 *
 * 编码解码 segwit 地址的 C 语言实现，兼容比特币网络标准。
 *
 * 作者：8891689/ChatGPT
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "bech32.h"
/* Bech32 字符集 */
static const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/* --- 内部函数 --- */

/* 计算 Bech32 校验和（polymod） */
static uint32_t bech32_polymod(const int *values, size_t values_len) {
    uint32_t chk = 1;
    for (size_t i = 0; i < values_len; i++) {
        int top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (uint32_t)values[i];
        for (int j = 0; j < 5; j++) {
            if ((top >> j) & 1) {
                switch(j) {
                    case 0: chk ^= 0x3b6a57b2; break;
                    case 1: chk ^= 0x26508e6d; break;
                    case 2: chk ^= 0x1ea119fa; break;
                    case 3: chk ^= 0x3d4233dd; break;
                    case 4: chk ^= 0x2a1462b3; break;
                }
            }
        }
    }
    return chk;
}

/* 将 HRP 扩展为校验和计算用的数组 */
static int bech32_hrp_expand(const char *hrp, int *output) {
    size_t hrp_len = strlen(hrp);
    for (size_t i = 0; i < hrp_len; i++) {
        output[i] = hrp[i] >> 5;
    }
    output[hrp_len] = 0;
    for (size_t i = 0; i < hrp_len; i++) {
        output[hrp_len + 1 + i] = hrp[i] & 31;
    }
    return (int)(2 * hrp_len + 1);
}

/* 校验 checksum 是否正确 */
static int bech32_verify_checksum(const char *hrp, const int *data, size_t data_len) {
    int hrp_expanded[256];
    int hrp_exp_len = bech32_hrp_expand(hrp, hrp_expanded);
    int values[256];
    size_t total_len = hrp_exp_len + data_len;
    if (total_len > 256) return 0;
    memcpy(values, hrp_expanded, hrp_exp_len * sizeof(int));
    memcpy(values + hrp_exp_len, data, data_len * sizeof(int));
    return (bech32_polymod(values, total_len) == 1);
}

/* 根据 HRP 与数据生成 6 个校验值 */
static void bech32_create_checksum(const char *hrp, const int *data, size_t data_len, int *checksum) {
    int hrp_expanded[256];
    int hrp_exp_len = bech32_hrp_expand(hrp, hrp_expanded);
    int values[256];
    size_t total_len = hrp_exp_len + data_len + 6;
    memcpy(values, hrp_expanded, hrp_exp_len * sizeof(int));
    memcpy(values + hrp_exp_len, data, data_len * sizeof(int));
    for (int i = 0; i < 6; i++) {
        values[hrp_exp_len + data_len + i] = 0;
    }
    uint32_t polymod = bech32_polymod(values, total_len) ^ 1;
    for (int i = 0; i < 6; i++) {
        checksum[i] = (polymod >> (5 * (5 - i))) & 31;
    }
}

/* 根据 HRP 与数据生成 Bech32 字符串 */
static char *bech32_encode(const char *hrp, const int *data, size_t data_len) {
    int checksum[6];
    bech32_create_checksum(hrp, data, data_len, checksum);
    size_t hrp_len = strlen(hrp);
    size_t output_len = hrp_len + 1 + data_len + 6;  /* hrp + '1' + 数据 + 校验值 */
    char *ret = malloc(output_len + 1);
    if (!ret) return NULL;
    strcpy(ret, hrp);
    ret[hrp_len] = '1';
    for (size_t i = 0; i < data_len; i++) {
        int d = data[i];
        if (d < 0 || d >= 32) { free(ret); return NULL; }
        ret[hrp_len + 1 + i] = CHARSET[d];
    }
    for (size_t i = 0; i < 6; i++) {
        ret[hrp_len + 1 + data_len + i] = CHARSET[checksum[i]];
    }
    ret[output_len] = '\0';
    return ret;
}

/* 解码 Bech32 字符串。
 * out_hrp: 保存 HRP 的缓冲区（至少 84 字节）。
 * out_data: 保存解码后数据的数组（调用者保证空间足够）。
 * out_data_len: 输出数据的个数（不含校验值）。
 * 返回 1 表示成功，0 表示失败。
 */
static int bech32_decode_impl(const char *bech, char *out_hrp, int *out_data, size_t *out_data_len) {
    size_t len = strlen(bech);
    if (len < 8 || len > 90) return 0;
    int has_lower = 0, has_upper = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = bech[i];
        if (c < 33 || c > 126) return 0;
        if (c >= 'a' && c <= 'z') has_lower = 1;
        if (c >= 'A' && c <= 'Z') has_upper = 1;
    }
    if (has_lower && has_upper) return 0;  /* 不允许混合大小写 */
    char *bech_copy = malloc(len + 1);
    if (!bech_copy) return 0;
    for (size_t i = 0; i < len; i++) {
        bech_copy[i] = tolower(bech[i]);
    }
    bech_copy[len] = '\0';
    int pos = -1;
    for (size_t i = 0; i < len; i++) {
        if (bech_copy[i] == '1') pos = i;
    }
    if (pos < 1 || pos + 7 > (int)len) { free(bech_copy); return 0; }
    size_t hrp_len = pos;
    memcpy(out_hrp, bech_copy, hrp_len);
    out_hrp[hrp_len] = '\0';
    size_t data_part_len = len - pos - 1;
    if (data_part_len < 6) { free(bech_copy); return 0; }
    for (size_t i = 0; i < data_part_len; i++) {
        char *p = strchr(CHARSET, bech_copy[pos + 1 + i]);
        if (!p) { free(bech_copy); return 0; }
        out_data[i] = p - CHARSET;
    }
    free(bech_copy);
    if (!bech32_verify_checksum(out_hrp, out_data, data_part_len)) {
        return 0;
    }
    if (data_part_len < 6) return 0;
    *out_data_len = data_part_len - 6;
    return 1;
}

/* 通用的位转换函数：将 in 数组（每个值占 frombits 位）转换为 tobits 位输出。
 * pad 为非零表示在不足时补零。
 * out 数组由调用者提供，outlen 输出转换后数组的长度。
 * 成功返回 1，失败返回 0。
 */
static int convertbits(const int *in, size_t inlen, int frombits, int tobits, int pad, int *out, size_t *outlen) {
    uint32_t acc = 0;
    int bits = 0;
    size_t out_idx = 0;
    uint32_t maxv = (1 << tobits) - 1;
    uint32_t max_acc = (1 << (frombits + tobits - 1)) - 1;
    for (size_t i = 0; i < inlen; i++) {
        int value = in[i];
        if (value < 0 || (value >> frombits)) return 0;
        acc = ((acc << frombits) | value) & max_acc;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            out[out_idx++] = (acc >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits > 0) {
            out[out_idx++] = (acc << (tobits - bits)) & maxv;
        }
    } else {
        if (bits >= frombits) return 0;
        if (((acc << (tobits - bits)) & maxv) != 0) return 0;
    }
    *outlen = out_idx;
    return 1;
}

/* 内部实现：解码 segwit 地址
 * addr: 输入的 Bech32 地址
 * hrp: 预期的 HRP
 * witver: 输出 witness 版本
 * witprog: 输出 witness 程序缓冲区（调用者保证空间足够）
 * witprog_len: 输入时为缓冲区大小，输出时为实际长度
 * 成功返回 1，失败返回 0。
 */
static int segwit_addr_decode_internal(const char *addr, const char *hrp, int *witver, uint8_t *witprog, size_t *witprog_len) {
    char hrp_decoded[84];
    int data[90];
    size_t data_len;
    if (!bech32_decode_impl(addr, hrp_decoded, data, &data_len)) return 0;
    if (strcmp(hrp_decoded, hrp) != 0) return 0;
    if (data_len < 1) return 0;
    *witver = data[0];
    int conv[200];
    size_t conv_len;
    if (!convertbits(data + 1, data_len - 1, 5, 8, 0, conv, &conv_len)) return 0;
    if (conv_len < 2 || conv_len > 40) return 0;
    if (*witver > 16) return 0;
    if (*witver == 0 && conv_len != 20 && conv_len != 32) return 0;
    if (*witprog_len < conv_len) return 0;
    for (size_t i = 0; i < conv_len; i++) {
        witprog[i] = (uint8_t)conv[i];
    }
    *witprog_len = conv_len;
    return 1;
}

/* 内部实现：编码 segwit 地址
 * hrp: 人类可读部分
 * witver: witness 版本
 * witprog: witness 程序数据
 * witprog_len: witness 程序长度
 * 成功时返回 malloc 分配的地址字符串，失败返回 NULL。
 */
static char *segwit_addr_encode_internal(const char *hrp, int witver, const uint8_t *witprog, size_t witprog_len) {
    int in[200];
    for (size_t i = 0; i < witprog_len; i++) {
        in[i] = witprog[i];
    }
    int five_bit[200];
    size_t five_bit_len;
    if (!convertbits(in, witprog_len, 8, 5, 1, five_bit, &five_bit_len)) return NULL;
    int data[201];
    data[0] = witver;
    memcpy(data + 1, five_bit, five_bit_len * sizeof(int));
    size_t data_len = five_bit_len + 1;
    char *ret = bech32_encode(hrp, data, data_len);
    if (ret == NULL) return NULL;
    /* 可选：验证编码结果 */
    int ver;
    uint8_t prog[40];
    size_t prog_len = sizeof(prog);
    if (!segwit_addr_decode_internal(ret, hrp, &ver, prog, &prog_len)) {
        free(ret);
        return NULL;
    }
    return ret;
}

/* --- 对外接口 --- */

/* segwit_addr_encode: 将 witness 程序编码为 Bech32 格式地址 */
int segwit_addr_encode(char *output, const char *hrp, int witver, const uint8_t *witprog, size_t witprog_len) {
    char *encoded = segwit_addr_encode_internal(hrp, witver, witprog, witprog_len);
    if (!encoded) return 0;
    strcpy(output, encoded);
    free(encoded);
    return 1;
}

/* segwit_addr_decode: 解码 Bech32 格式的 segwit 地址 */
int segwit_addr_decode(const char *addr, const char *hrp, int *witver, uint8_t *witprog, size_t *witprog_len) {
    return segwit_addr_decode_internal(addr, hrp, witver, witprog, witprog_len);
}

