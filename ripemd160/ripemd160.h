/*Author: 8891689
 * Assist in creation ：ChatGPT 
 */
#ifndef RIPEMD160_H
#define RIPEMD160_H

#include <stdint.h>
#include <stddef.h>

#define RIPEMD160_DIGEST_LENGTH 20  // 160位 = 20字节

// RIPEMD-160上下文结构体，用于保存算法中间状态
typedef struct {
    uint32_t state[5];    // 五个32位状态（A,B,C,D,E）
    uint64_t bitlen;      // 已处理消息的总长度（单位：比特）
    uint8_t data[64];     // 数据缓冲区（512位）
    size_t datalen;       // 当前缓冲区数据字节数
} RIPEMD160_CTX;

#ifdef __cplusplus
extern "C" {
#endif

// 初始化RIPEMD-160上下文
void ripemd160_init(RIPEMD160_CTX *ctx);

// 更新数据，可以多次调用以处理任意长度数据
void ripemd160_update(RIPEMD160_CTX *ctx, const uint8_t *data, size_t len);

// 完成哈希计算，将最终结果输出到hash数组（20字节）
void ripemd160_final(RIPEMD160_CTX *ctx, uint8_t hash[RIPEMD160_DIGEST_LENGTH]);

// 辅助函数，一次性计算输入数据的RIPEMD-160哈希值
void ripemd160(const uint8_t *data, size_t len, uint8_t hash[RIPEMD160_DIGEST_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif // RIPEMD160_H

