/*
 * base58_example.c
 * 一个 Base58 与 Base58Check 编码／解码的 C 语言实现，兼容比特币网络标准。
 * 依赖 OpenSSL 用于 SHA256 计算，编译时请链接 -lcrypto
 * gcc -o base58_example base58_example.c -lcrypto
 * 实现了 Base58 编码／解码以及 Base58Check 编码／解码。
 * 此代码使用了 OpenSSL 库来计算 SHA256 校验和，因此编译时需要链接 OpenSSL
 * 作者：ChatGPT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "sha256.h"  // 对应的头文件

/* Bitcoin 使用的 Base58 字母表 */
static const char *BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/*
 * 函数：base58_encode
 * -------------------
 * 对输入的二进制数据进行 Base58 编码。
 *
 * 参数：
 *   data     - 输入的二进制数据
 *   data_len - 数据长度
 *
 * 返回：
 *   成功时返回经过 malloc 分配的 null 结尾的字符串（调用者负责 free）；
 *   出错时返回 NULL。
 */
char *base58_encode(const unsigned char *data, size_t data_len) {
    size_t zeros = 0;
    while (zeros < data_len && data[zeros] == 0)
        zeros++;

    /* 估计输出长度，公式：encoded_size ≈ data_len * log(256)/log(58) + 1
       这里取：data_len * 138/100 + 2 */
    size_t size = data_len * 138 / 100 + 2;
    char *b58 = malloc(size);
    if (!b58)
        return NULL;
    size_t b58_len = 0;

    /* 复制一份数据用于计算，因算法会修改数据 */
    unsigned char *buffer = malloc(data_len);
    if (!buffer) {
        free(b58);
        return NULL;
    }
    memcpy(buffer, data, data_len);

    size_t start = zeros;
    while (start < data_len) {
        int remainder = 0;
        for (size_t i = start; i < data_len; i++) {
            int num = remainder * 256 + buffer[i];
            buffer[i] = num / 58;
            remainder = num % 58;
        }
        b58[b58_len++] = BASE58_ALPHABET[remainder];
        while (start < data_len && buffer[start] == 0)
            start++;
    }
    free(buffer);

    /* 对于原始数据前导的 0x00，每个都编码成字母表第一个字符 '1' */
    for (size_t i = 0; i < zeros; i++) {
        b58[b58_len++] = BASE58_ALPHABET[0];
    }

    /* 目前 b58 数组中的字符顺序为逆序，下面将其反转 */
    for (size_t i = 0; i < b58_len / 2; i++) {
        char temp = b58[i];
        b58[i] = b58[b58_len - 1 - i];
        b58[b58_len - 1 - i] = temp;
    }
    b58[b58_len] = '\0';
    return b58;
}

/*
 * 函数：base58_decode
 * ---------------------
 * 对 Base58 编码的字符串进行解码，返回解码后的二进制数据。
 *
 * 参数：
 *   b58         - Base58 编码的字符串
 *   result_len  - 输出参数，保存解码后的数据长度
 *
 * 返回：
 *   成功时返回 malloc 分配的二进制数据（调用者负责 free），
 *   出错时返回 NULL。
 */
unsigned char *base58_decode(const char *b58, size_t *result_len) {
    /* 跳过可能的前导空格 */
    while (*b58 == ' ')
        b58++;

    size_t b58_len = strlen(b58);

    /* 统计前导的字母 '1' 个数（代表原数据中的 0x00） */
    size_t zeros = 0;
    while (zeros < b58_len && b58[zeros] == BASE58_ALPHABET[0])
        zeros++;

    /* 估计输出缓冲区大小，公式：bin_size ≈ b58_len * log(58)/log(256) + 1
       这里取：b58_len * 733/1000 + 1 （因为 log(58)/log(256) ≈ 0.733） */
    size_t size = b58_len * 733 / 1000 + 1;
    unsigned char *bin = calloc(size, 1);
    if (!bin)
        return NULL;

    for (size_t i = 0; i < b58_len; i++) {
        const char *p = strchr(BASE58_ALPHABET, b58[i]);
        if (!p) {
            free(bin);
            return NULL;  /* 非法字符 */
        }
        int digit = p - BASE58_ALPHABET;
        int carry = digit;
        /* 注意：这里使用 int 型变量 j，假定 size 不会太大 */
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

    /* 最终输出 = 前导零（由 '1' 转换而来） + 剩余的二进制数据 */
    size_t decoded_size = zeros + (size - i);
    unsigned char *decoded = malloc(decoded_size);
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
 * 函数：base58_encode_check
 * --------------------------
 * 对数据进行 Base58Check 编码，先对数据计算双 SHA256 得到校验和（取前 4 字节），
 * 然后将数据与校验和拼接后再进行 Base58 编码。
 *
 * 参数：
 *   data     - 输入的二进制数据
 *   data_len - 数据长度
 *
 * 返回：
 *   成功时返回经过 malloc 分配的 null 结尾字符串（调用者负责 free），
 *   出错时返回 NULL。
 */
char *base58_encode_check(const unsigned char *data, size_t data_len) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];

    /* 先计算 SHA256 */
    SHA256(data, data_len, hash1);
    /* 再对 hash1 计算 SHA256 */
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

    /* 拼接数据与校验和（取 hash2 前 4 字节） */
    size_t new_len = data_len + 4;
    unsigned char *buffer = malloc(new_len);
    if (!buffer)
        return NULL;
    memcpy(buffer, data, data_len);
    memcpy(buffer + data_len, hash2, 4);

    char *encoded = base58_encode(buffer, new_len);
    free(buffer);
    return encoded;
}

/*
 * 函数：base58_decode_check
 * ---------------------------
 * 对 Base58Check 编码的字符串进行解码，并验证校验和是否正确。
 *
 * 参数：
 *   b58         - Base58Check 编码的字符串
 *   result_len  - 输出参数，保存解码后原始数据的长度（不含校验和）
 *
 * 返回：
 *   成功时返回 malloc 分配的原始数据（调用者负责 free），
 *   校验和验证失败或出错时返回 NULL。
 */
unsigned char *base58_decode_check(const char *b58, size_t *result_len) {
    size_t bin_len;
    unsigned char *bin = base58_decode(b58, &bin_len);
    if (!bin)
        return NULL;
    if (bin_len < 4) {  /* 至少应包含 4 字节校验和 */
        free(bin);
        return NULL;
    }

    size_t payload_len = bin_len - 4;
    unsigned char *payload = malloc(payload_len);
    if (!payload) {
        free(bin);
        return NULL;
    }
    memcpy(payload, bin, payload_len);

    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];
    SHA256(payload, payload_len, hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

    /* 校验解码数据最后 4 字节是否与 hash2 的前 4 字节一致 */
    if (memcmp(hash2, bin + payload_len, 4) != 0) {
        free(bin);
        free(payload);
        return NULL;  /* 校验和错误 */
    }
    free(bin);
    if (result_len)
        *result_len = payload_len;
    return payload;
}

/* 一个简单的测试示例 */
int main(void) {
    const char *text = "Hello, World!";
    size_t text_len = strlen(text);
    printf("原始数据: %s\n", text);

    /* Base58 编码 */
    char *encoded = base58_encode((const unsigned char *)text, text_len);
    if (!encoded) {
        fprintf(stderr, "base58_encode 出错\n");
        return 1;
    }
    printf("Base58 编码: %s\n", encoded);

    /* Base58 解码 */
    size_t decoded_len;
    unsigned char *decoded = base58_decode(encoded, &decoded_len);
    if (!decoded) {
        fprintf(stderr, "base58_decode 出错\n");
        free(encoded);
        return 1;
    }
    printf("Base58 解码: ");
    for (size_t i = 0; i < decoded_len; i++) {
        putchar(decoded[i]);
    }
    printf("\n");

    /* Base58Check 编码 */
    char *encoded_check = base58_encode_check((const unsigned char *)text, text_len);
    if (!encoded_check) {
        fprintf(stderr, "base58_encode_check 出错\n");
        free(encoded);
        free(decoded);
        return 1;
    }
    printf("Base58Check 编码: %s\n", encoded_check);

    /* Base58Check 解码 */
    unsigned char *decoded_check = base58_decode_check(encoded_check, &decoded_len);
    if (!decoded_check) {
        fprintf(stderr, "base58_decode_check 出错（校验和错误？）\n");
        free(encoded);
        free(decoded);
        free(encoded_check);
        return 1;
    }
    printf("Base58Check 解码: ");
    for (size_t i = 0; i < decoded_len; i++) {
        putchar(decoded_check[i]);
    }
    printf("\n");

    free(encoded);
    free(decoded);
    free(encoded_check);
    free(decoded_check);
    return 0;
}

