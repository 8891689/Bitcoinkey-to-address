/*
 * bech32.h
 *
 * 内部实现：编码解码 segwit 地址的 C 语言实现，兼容比特币网络标准。
 *
 * 作者：8891689/ChatGPT
 */

#ifndef BECH32_H
#define BECH32_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * segwit_addr_encode - 使用 Bech32 格式对 segwit 地址进行编码
 *
 * @output: 输出缓冲区，用于存放 null 结尾的地址字符串（调用者保证足够大）
 * @hrp: 人类可读部分（例如 "bc"）
 * @witver: witness 版本（0～16）
 * @witprog: witness 程序（二进制数据）
 * @witprog_len: witness 程序的字节长度
 *
 * 成功返回 1，失败返回 0。
 */
int segwit_addr_encode(char *output, const char *hrp, int witver, const uint8_t *witprog, size_t witprog_len);

/**
 * segwit_addr_decode - 解码 Bech32 格式的 segwit 地址
 *
 * @addr: 输入的 Bech32 地址字符串
 * @hrp: 预期的人类可读部分（例如 "bc"）
 * @witver: 输出参数，保存解析出的 witness 版本
 * @witprog: 输出缓冲区，用于保存解析出的 witness 程序（二进制数据）
 * @witprog_len: 输入时为 witprog 缓冲区大小；输出时保存实际数据长度
 *
 * 成功返回 1，失败返回 0。
 */
int segwit_addr_decode(const char *addr, const char *hrp, int *witver, uint8_t *witprog, size_t *witprog_len);

#ifdef __cplusplus
}
#endif

#endif /* bech32_h */

