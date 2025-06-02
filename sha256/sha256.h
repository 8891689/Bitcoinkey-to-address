#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 定義 SHA-256 輸出長度（字節）
#define SHA256_BLOCK_SIZE 32

// 定義 SHA256 上下文結構體
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

// 初始化上下文
void sha256_init(SHA256_CTX *ctx);
// 更新上下文：處理數據塊
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);
// 結束計算：輸出最終哈希值
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);
// 一次性計算整個數據的 sha256 哈希值
void sha256(const uint8_t *data, size_t len, uint8_t *hash);

#ifdef __cplusplus
}
#endif

#endif // SHA256_H

