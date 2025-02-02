/*
 * base58.c
 *
 * 一个 Base58 与 Base58Check 编码／解码的 C 语言实现，兼容比特币网络标准。
 *
 * 作者：8891689/ChatGPT
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "base58.h"


#include "../sha256/sha256.h"

/*
 * 注意：此处引用 SHA-256 的头文件采用相对路径，
 * 根据你的工程结构，请确保路径正确。
 */


/* Bitcoin 使用的 Base58 字母表 */
static const char *BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/*
 * 内部函数：base58_encode
 *
 * 对输入的二进制数据进行 Base58 编码，返回 malloc 分配的 null 结尾字符串。
 * 调用者需要使用 free() 释放返回的内存。
 */
static char *base58_encode(const uint8_t *data, size_t data_len) {
    size_t zeros = 0;
    while (zeros < data_len && data[zeros] == 0)
        zeros++;

    /* 估计输出长度：data_len * log(256)/log(58) + 1
       这里取：data_len * 138/100 + 2 */
    size_t size = data_len * 138 / 100 + 2;
    char *buffer = malloc(size);
    if (!buffer)
        return NULL;
    size_t b58_len = 0;

    /* 复制一份数据用于计算（算法会修改数据） */
    uint8_t *input = malloc(data_len);
    if (!input) {
        free(buffer);
        return NULL;
    }
    memcpy(input, data, data_len);

    size_t start = zeros;
    while (start < data_len) {
        int remainder = 0;
        for (size_t i = start; i < data_len; i++) {
            int num = remainder * 256 + input[i];
            input[i] = num / 58;
            remainder = num % 58;
        }
        buffer[b58_len++] = BASE58_ALPHABET[remainder];
        while (start < data_len && input[start] == 0)
            start++;
    }
    free(input);

    /* 每个原数据中的前导 0x00 转换为字母表中第一个字符 '1' */
    for (size_t i = 0; i < zeros; i++) {
        buffer[b58_len++] = BASE58_ALPHABET[0];
    }

    /* 结果目前是逆序，需要反转 */
    for (size_t i = 0; i < b58_len / 2; i++) {
        char temp = buffer[i];
        buffer[i] = buffer[b58_len - 1 - i];
        buffer[b58_len - 1 - i] = temp;
    }
    buffer[b58_len] = '\0';
    return buffer;
}

/*
 * 内部函数：base58_decode
 *
 * 对 Base58 编码字符串进行解码，返回 malloc 分配的二进制数据缓冲区，
 * 并在 result_len 中保存解码后数据长度。
 * 调用者需要使用 free() 释放返回的内存。
 */
static uint8_t *base58_decode(const char *b58, size_t *result_len) {
    /* 跳过前导空格 */
    while (*b58 == ' ')
        b58++;
    size_t b58_len = strlen(b58);

    /* 统计前导 '1' 的个数（代表原数据中的 0x00） */
    size_t zeros = 0;
    while (zeros < b58_len && b58[zeros] == BASE58_ALPHABET[0])
        zeros++;

    /* 估计输出缓冲区大小：b58_len * log(58)/log(256) + 1
       这里取：b58_len * 733/1000 + 1 （约 0.733） */
    size_t size = b58_len * 733 / 1000 + 1;
    uint8_t *bin = calloc(size, 1);
    if (!bin)
        return NULL;

    for (size_t i = 0; i < b58_len; i++) {
        const char *p = strchr(BASE58_ALPHABET, b58[i]);
        if (!p) {
            free(bin);
            return NULL;  /* 出现非法字符 */
        }
        int digit = p - BASE58_ALPHABET;
        int carry = digit;
        for (int j = (int)size - 1; j >= 0; j--) {
            carry += 58 * bin[j];
            bin[j] = carry % 256;
            carry /= 256;
        }
        if (carry != 0) {  /* 溢出 */
            free(bin);
            return NULL;
        }
    }

    /* 跳过 bin 数组中前导的零 */
    size_t i = 0;
    while (i < size && bin[i] == 0)
        i++;

    /* 最终输出 = 前导零（由 '1' 转换而来） + 剩余二进制数据 */
    size_t decoded_size = zeros + (size - i);
    uint8_t *decoded = malloc(decoded_size);
    if (!decoded) {
        free(bin);
        return NULL;
    }
    memset(decoded, 0, zeros);
    memcpy(decoded + zeros, bin + i, size - i);
    free(bin);
    if (result_len)
        *result_len = decoded_size;
    return decoded;
}

/*
 * Base58Check 编码：
 * 先对数据计算双 SHA-256，取前 4 字节作为校验和，
 * 然后将数据与校验和拼接后进行 Base58 编码。
 */
char *base58_encode_check(const uint8_t *data, size_t data_len) {
    uint8_t hash1[32], hash2[32];
    sha256(data, data_len, hash1);
    sha256(hash1, 32, hash2);

    size_t new_len = data_len + 4;
    uint8_t *buffer = malloc(new_len);
    if (!buffer)
        return NULL;
    memcpy(buffer, data, data_len);
    memcpy(buffer + data_len, hash2, 4);

    char *encoded = base58_encode(buffer, new_len);
    free(buffer);
    return encoded;
}

/*
 * Base58Check 解码：
 * 解码 Base58Check 字符串并验证校验和（前提是编码数据至少含 4 字节校验和）。
 */
uint8_t *base58_decode_check(const char *b58, size_t *result_len) {
    size_t bin_len;
    uint8_t *bin = base58_decode(b58, &bin_len);
    if (!bin)
        return NULL;
    if (bin_len < 4) {  /* 至少需有 4 字节校验和 */
        free(bin);
        return NULL;
    }

    size_t payload_len = bin_len - 4;
    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        free(bin);
        return NULL;
    }
    memcpy(payload, bin, payload_len);

    uint8_t hash1[32], hash2[32];
    sha256(payload, payload_len, hash1);
    sha256(hash1, 32, hash2);

    if (memcmp(hash2, bin + payload_len, 4) != 0) {
        free(bin);
        free(payload);
        return NULL;  /* 校验和不匹配 */
    }
    free(bin);
    if (result_len)
        *result_len = payload_len;
    return payload;
}

/*
 * 以下为对外接口的包装函数，调整了函数名称以适配你的代码：
 */

/* 
 * b58enc - 封装 base58_encode，将 malloc 分配的字符串复制到用户提供的缓冲区。
 */
int b58enc(char *b58, size_t *b58len, const uint8_t *bin, size_t binlen) {
    char *encoded = base58_encode(bin, binlen);
    if (!encoded)
        return 0;
    size_t len = strlen(encoded);
    if (*b58len < len + 1) {
        free(encoded);
        return 0;
    }
    strcpy(b58, encoded);
    *b58len = len;
    free(encoded);
    return 1;
}

/*
 * b58tobin - 封装 base58_decode，将解码后的数据复制到用户提供的缓冲区。
 */
int b58tobin(uint8_t *bin, size_t *binlen, const char *b58, size_t b58len) {
    /* 复制 b58 字符串到临时缓冲区以确保 null 结尾 */
    char *temp = malloc(b58len + 1);
    if (!temp)
        return 0;
    memcpy(temp, b58, b58len);
    temp[b58len] = '\0';

    size_t decoded_len;
    uint8_t *decoded = base58_decode(temp, &decoded_len);
    free(temp);
    if (!decoded)
        return 0;
    if (*binlen < decoded_len) {
        free(decoded);
        return 0;
    }
    memcpy(bin, decoded, decoded_len);
    *binlen = decoded_len;
    free(decoded);
    return 1;
}

