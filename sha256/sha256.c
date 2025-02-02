/* sha256.c */
/*
    SHA256 implementation, source file.

    This implementation was written by Kent "ethereal" Williams-King and is
    hereby released into the public domain. Do what you wish with it.

    No guarantees as to the correctness of the implementation are provided.
*/
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "sha256.h"  // 对应的头文件

/* 初始哈希值 */
static const uint32_t sha256_initial_h[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/* 64 个轮常量 */
static const uint32_t sha256_round_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* 循环右移函数 */
static inline uint32_t sha256_ror(uint32_t input, uint32_t by) {
    return (input >> by) | (input << (32 - by));
}

/* 从 4 字节数组（大端序）中读取 32 位整数 */
uint32_t sha256_endian_read32(const uint8_t *input) {
    return ((uint32_t)input[0] << 24) |
           ((uint32_t)input[1] << 16) |
           ((uint32_t)input[2] << 8)  |
           ((uint32_t)input[3]);
}

/* 将 32 位整数写入 4 字节数组（大端序） */
void sha256_endian_reverse32(uint32_t input, uint8_t *output) {
    output[0] = (uint8_t)(input >> 24);
    output[1] = (uint8_t)(input >> 16);
    output[2] = (uint8_t)(input >> 8);
    output[3] = (uint8_t)input;
}

/* 将 64 位整数写入 8 字节数组（大端序） */
void sha256_endian_reverse64(uint64_t input, uint8_t *output) {
    output[0] = (uint8_t)(input >> 56);
    output[1] = (uint8_t)(input >> 48);
    output[2] = (uint8_t)(input >> 40);
    output[3] = (uint8_t)(input >> 32);
    output[4] = (uint8_t)(input >> 24);
    output[5] = (uint8_t)(input >> 16);
    output[6] = (uint8_t)(input >> 8);
    output[7] = (uint8_t)input;
}

/*
 * 主 SHA-256 函数
 * data: 输入数据
 * len: 输入数据长度（字节）
 * output: 输出 32 字节的哈希值
 */
void sha256(const void *data, uint64_t len, void *output) {
    const uint8_t *data_bytes = (const uint8_t*)data;
    // 计算填充后的总长度：总长度为最小的64的倍数，且 >= len+9
    uint64_t padded_len = ((len + 9 + 63) / 64) * 64;
    uint8_t *padded = (uint8_t*)malloc(padded_len);
    if (!padded) {
        // 内存不足时不执行计算
        return;
    }
    
    // 将原始数据复制到 padded 缓冲区
    memcpy(padded, data_bytes, len);
    // 在数据末尾添加 0x80
    padded[len] = 0x80;
    // 填充 0x00（从 len+1 到 padded_len - 8）
    memset(padded + len + 1, 0, padded_len - len - 9);
    // 在 padded 的最后 8 字节写入消息长度（以比特为单位，使用大端格式）
    uint64_t bits_len = len * 8;
    sha256_endian_reverse64(bits_len, padded + padded_len - 8);
    
    // 初始化哈希状态
    uint32_t h[8];
    for (int i = 0; i < 8; i++) {
        h[i] = sha256_initial_h[i];
    }
    
    uint32_t w[64];
    // 对每个 64 字节块进行处理
    for (uint64_t block = 0; block < padded_len; block += 64) {
        // 将前 16 个 32 位字读入消息调度数组
        for (int i = 0; i < 16; i++) {
            w[i] = sha256_endian_read32(padded + block + i * 4);
        }
        // 扩展消息调度数组 w[16..63]
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = sha256_ror(w[i - 15], 7) ^ sha256_ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = sha256_ror(w[i - 2], 17) ^ sha256_ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        
        // 初始化工作变量
        uint32_t a = h[0];
        uint32_t b = h[1];
        uint32_t c = h[2];
        uint32_t d = h[3];
        uint32_t e = h[4];
        uint32_t f = h[5];
        uint32_t g = h[6];
        uint32_t hh = h[7];
        
        // 主压缩循环
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = sha256_ror(e, 6) ^ sha256_ror(e, 11) ^ sha256_ror(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = hh + S1 + ch + sha256_round_k[i] + w[i];
            uint32_t S0 = sha256_ror(a, 2) ^ sha256_ror(a, 13) ^ sha256_ror(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            
            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        
        // 将本块处理结果累加到哈希状态
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }
    
    free(padded);
    
    // 将最终哈希值以大端格式写入输出缓冲区（32 字节）
    for (int i = 0; i < 8; i++) {
        sha256_endian_reverse32(h[i], ((uint8_t*)output) + i * 4);
    }
}

