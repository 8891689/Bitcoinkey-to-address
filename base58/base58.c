/*author：https://github.com/8891689
 * Assist in creation ：ChatGPT 
 */
#include "base58.h"
#include "../sha256/sha256.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

/* Bitcoin 使用的 Base58 字母表 */
static const char *BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/*
 * 内部函數：base58_encode
 */
static char *base58_encode(const uint8_t *data, size_t data_len) {
    size_t zeros = 0;
    while (zeros < data_len && data[zeros] == 0)
        zeros++;

    /* 估計輸出長度：data_len * log(256)/log(58) + 1
       這裡取：data_len * 138/100 + 2 */
    size_t size = data_len * 138 / 100 + 2;
    char *buffer = (char *)malloc(size);
    if (!buffer)
        return NULL;
    size_t b58_len = 0;

    /* 複製一份數據用於計算（算法會修改數據） */
    uint8_t *input = (uint8_t *)malloc(data_len);
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

    /* 每個原數據中的前導 0x00 轉換為字母表中第一個字符 '1' */
    for (size_t i = 0; i < zeros; i++) {
        buffer[b58_len++] = BASE58_ALPHABET[0];
    }

    /* 結果目前是逆序，需要反轉 */
    for (size_t i = 0; i < b58_len / 2; i++) {
        char temp = buffer[i];
        buffer[i] = buffer[b58_len - 1 - i];
        buffer[b58_len - 1 - i] = temp;
    }
    buffer[b58_len] = '\0';
    return buffer;
}

/*
 * 内部函數：base58_decode
 */
static uint8_t *base58_decode(const char *b58, size_t *result_len) {
    while (*b58 == ' ')
        b58++;
    size_t b58_len = strlen(b58);

    /* 統計前導 '1' 的個數（代表原數據中的 0x00） */
    size_t zeros = 0;
    while (zeros < b58_len && b58[zeros] == BASE58_ALPHABET[0])
        zeros++;

    /* 估計輸出緩衝區大小：b58_len * log(58)/log(256) + 1
       這裡取：b58_len * 733/1000 + 1 （約 0.733） */
    size_t size = b58_len * 733 / 1000 + 1;
    uint8_t *bin = (uint8_t *)calloc(size, 1);
    if (!bin)
        return NULL;

    for (size_t i = 0; i < b58_len; i++) {
        const char *p = strchr(BASE58_ALPHABET, b58[i]);
        if (!p) {
            free(bin);
            return NULL;  /* 出現非法字符 */
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

    /* 跳過 bin 陣列中前導的零 */
    size_t i = 0;
    while (i < size && bin[i] == 0)
        i++;

    /* 最終輸出 = 前導零（由 '1' 轉換而來） + 剩餘二進制數據 */
    size_t decoded_size = zeros + (size - i);
    uint8_t *decoded = (uint8_t *)malloc(decoded_size);
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
 * Base58Check 編碼：
 * 先對數據計算雙 SHA-256，取前 4 字節作為校驗和，
 * 然後將數據與校驗和拼接後進行 Base58 編碼。
 */
char *base58_encode_check(const uint8_t *data, size_t data_len) {
    uint8_t hash1[SHA256_BLOCK_SIZE], hash2[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, hash1);

    sha256_init(&ctx);
    sha256_update(&ctx, hash1, SHA256_BLOCK_SIZE);
    sha256_final(&ctx, hash2);

    size_t new_len = data_len + 4;
    uint8_t *buffer = (uint8_t *)malloc(new_len);
    if (!buffer)
        return NULL;
    memcpy(buffer, data, data_len);
    memcpy(buffer + data_len, hash2, 4);

    char *encoded = base58_encode(buffer, new_len);
    free(buffer);
    return encoded;
}

/*
 * Base58Check 解碼：
 */
uint8_t *base58_decode_check(const char *b58, size_t *result_len) {
    size_t bin_len;
    uint8_t *bin = base58_decode(b58, &bin_len);
    if (!bin)
        return NULL;
    if (bin_len < 4) {  /* 至少需有 4 字節校驗和 */
        free(bin);
        return NULL;
    }

    size_t payload_len = bin_len - 4;
    uint8_t *payload = (uint8_t *)malloc(payload_len);
    if (!payload) {
        free(bin);
        return NULL;
    }
    memcpy(payload, bin, payload_len);

    uint8_t hash1[SHA256_BLOCK_SIZE], hash2[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, payload, payload_len);
    sha256_final(&ctx, hash1);

    sha256_init(&ctx);
    sha256_update(&ctx, hash1, SHA256_BLOCK_SIZE);
    sha256_final(&ctx, hash2);

    if (memcmp(hash2, bin + payload_len, 4) != 0) {
        free(bin);
        free(payload);
        return NULL;  /* 校驗和不匹配 */
    }
    free(bin);
    if (result_len)
        *result_len = payload_len;
    return payload;
}

/*
 * 以下為對外接口的封裝函數：
 */

/*
 * b58enc - 封裝 base58_encode
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
 * b58tobin - 封裝 base58_decode
 */
int b58tobin(uint8_t *bin, size_t *binlen, const char *b58, size_t b58len) {
    char *temp = (char *)malloc(b58len + 1);
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



