/*base58.h
 *Author: 8891689
 *Assist in creation ：ChatGPT 
 */
#ifndef BASE58_H
#define BASE58_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * b58enc - 将二进制数据编码为 Base58 字符串。
 */
int b58enc(char *b58, size_t *b58len, const uint8_t *bin, size_t binlen);

/**
 * b58tobin - 将 Base58 字符串解码为二进制数据。
 */
int b58tobin(uint8_t *bin, size_t *binlen, const char *b58, size_t b58len);

/**
 * base58_encode_check - 对数据进行 Base58Check 编码（先计算双 SHA-256 校验和）。
 */
char *base58_encode_check(const uint8_t *data, size_t data_len);

/**
 * base58_decode_check - 对 Base58Check 编码的字符串解码，并验证校验和。
 */
uint8_t *base58_decode_check(const char *b58, size_t *result_len);

#ifdef __cplusplus
}
#endif

#endif /* base58_H */
