#ifndef BASE58_H
#define BASE58_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 封裝的 Base58 編碼接口，將二進制數據編碼到 b58 字符串中
// b58: 輸出緩衝區；b58len: 輸出緩衝區大小（輸入時表示空間大小，輸出時返回實際長度）
// 返回 1 表示成功，0 表示失敗。
int b58enc(char *b58, size_t *b58len, const uint8_t *bin, size_t binlen);

// 封裝的 Base58 解碼接口，將 b58 字符串解碼回二進制數據
// bin: 輸出緩衝區；binlen: 輸出緩衝區大小（輸入時表示空間大小，輸出時返回實際解碼長度）
// 返回 1 表示成功，0 表示失敗。
int b58tobin(uint8_t *bin, size_t *binlen, const char *b58, size_t b58len);

// Base58Check 編碼：對輸入數據先做雙 SHA-256，取前 4 字節作為校驗和，再將數據+校驗和進行 Base58 編碼
char *base58_encode_check(const uint8_t *data, size_t data_len);

// Base58Check 解碼：解碼後檢查校驗和正確性，若正確返回 payload（去除 4 字節校驗碼），否則返回 NULL
uint8_t *base58_decode_check(const char *b58, size_t *result_len);

#ifdef __cplusplus
}
#endif

#endif // BASE58_H

