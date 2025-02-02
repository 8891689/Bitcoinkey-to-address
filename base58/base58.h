/*
 * base58.h
 *
 * 一个 Base58 与 Base58Check 编码／解码的 C 语言实现，兼容比特币网络标准。
 *
 * 作者：8891689/ChatGPT
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
 *
 * @b58: 输出缓冲区，用于保存 null 结尾的 Base58 字符串。
 * @b58len: 输入时传入输出缓冲区大小；输出时保存编码后字符串的长度（不含结尾 0）。
 * @bin: 输入二进制数据。
 * @binlen: 输入数据长度（字节）。
 *
 * 成功返回 1；如果输出缓冲区不足或出错返回 0。
 */
int b58enc(char *b58, size_t *b58len, const uint8_t *bin, size_t binlen);

/**
 * b58tobin - 将 Base58 字符串解码为二进制数据。
 *
 * @bin: 输出缓冲区，用于保存解码后的二进制数据。
 * @binlen: 输入时传入输出缓冲区大小；输出时保存实际解码后数据长度。
 * @b58: 输入的 Base58 字符串（不一定需要 null 结尾，但须提供长度）。
 * @b58len: 输入 Base58 字符串的长度。
 *
 * 成功返回 1；如果解码出错或输出缓冲区不足返回 0。
 */
int b58tobin(uint8_t *bin, size_t *binlen, const char *b58, size_t b58len);

/**
 * base58_encode_check - 对数据进行 Base58Check 编码（先计算双 SHA-256 校验和）。
 *
 * @data: 输入数据。
 * @data_len: 数据长度（字节）。
 *
 * 返回一个经 malloc 分配的 null 结尾字符串，出错时返回 NULL。
 * 调用者负责释放返回的内存。
 */
char *base58_encode_check(const uint8_t *data, size_t data_len);

/**
 * base58_decode_check - 对 Base58Check 编码的字符串解码，并验证校验和。
 *
 * @b58: 输入的 Base58Check 字符串（null 结尾）。
 * @result_len: 输出参数，保存解码后数据长度（不含 4 字节校验和）。
 *
 * 返回一个经 malloc 分配的二进制数据缓冲区，出错时返回 NULL。
 * 调用者负责释放返回的内存。
 */
uint8_t *base58_decode_check(const char *b58, size_t *result_len);

#ifdef __cplusplus
}
#endif

#endif /* base58_H */

