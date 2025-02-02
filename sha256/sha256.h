/*
    SHA256 implementation, header file.

    This implementation was written by Kent "ethereal" Williams-King and is
    hereby released into the public domain. Do what you wish with it.

    No guarantees as to the correctness of the implementation are provided.
*/
#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

/*
 * 计算 SHA-256 哈希值
 * data: 输入数据指针
 * len: 输入数据长度（字节）
 * output: 输出 32 字节哈希值的缓冲区（必须预先分配 32 字节）
 */
void sha256(const void *data, uint64_t len, void *output);

#endif

