/*🟑 author：github.com/8891689
     gcc -O3 -o h hash160.c sha256.c base58.c bech32.c ripemd160.c
    🟑*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sha256/sha256.h"
#include "ripemd160/ripemd160.h"
#include "base58/base58.h"
#include "bech32/bech32.h"

/* 将 hex 字符串转换为二进制数据 */
int hex2bin(const char *hex, uint8_t *bin, size_t bin_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 != bin_len) {
        return -1;
    }
    for (size_t i = 0; i < bin_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%02x", &byte) != 1) {
            return -1;
        }
        bin[i] = (uint8_t)byte;
    }
    return 0;
}

/* 计算 hash160 = RIPEMD160(SHA256(data)) */
void hash160(const uint8_t *data, size_t data_len, uint8_t *out) {
    uint8_t sha[SHA256_BLOCK_SIZE];
    sha256(data, data_len, sha);
    ripemd160(sha, SHA256_BLOCK_SIZE, out);
}

/* 根据版本字节和 20 字节数据生成 Base58Check 地址 */
int base58check_encode(uint8_t version, const uint8_t *hash20, char *address, size_t addr_len) {
    uint8_t payload[21];
    payload[0] = version;
    memcpy(payload + 1, hash20, 20);

    uint8_t hash1[SHA256_BLOCK_SIZE];
    uint8_t hash2[SHA256_BLOCK_SIZE];
    sha256(payload, 21, hash1);
    sha256(hash1, SHA256_BLOCK_SIZE, hash2);

    uint8_t full[25];
    memcpy(full, payload, 21);
    memcpy(full + 21, hash2, 4);

    size_t encoded_len_temp = addr_len;
    if (!b58enc(address, &encoded_len_temp, full, 25)) {
         return -1;
    }
    return 0;
}

/*
 * 根据输入的 Hash160（40 字符 Hex）和地址类型生成地址
 */
char *hash_to_address(const char *hash_hex, const char *address_type) {
    if (strlen(hash_hex) != 40) {
        fprintf(stderr, "Error: Hash160 必须为 40 个十六进制字符。\n");
        return NULL;
    }
    uint8_t hash[RIPEMD160_DIGEST_LENGTH] = {0};
    if (hex2bin(hash_hex, hash, RIPEMD160_DIGEST_LENGTH) != 0) {
        fprintf(stderr, "Error: 无效的 Hash160 十六进制字符串。\n");
        return NULL;
    }

    char *address = (char *)malloc(100 * sizeof(char));
    if (address == NULL) {
        fprintf(stderr, "Error: 内存分配失败。\n");
        return NULL;
    }
    memset(address, 0, 100);

    if (strcmp(address_type, "P2PKH") == 0) {
        if (base58check_encode(0x00, hash, address, 100) != 0) {
            fprintf(stderr, "Error: P2PKH 地址生成失败。\n"); free(address); return NULL;
        }
    } else if (strcmp(address_type, "P2SH") == 0) {
        if (base58check_encode(0x05, hash, address, 100) != 0) {
            fprintf(stderr, "Error: P2SH 地址生成失败。\n"); free(address); return NULL;
        }
    } else if (strcmp(address_type, "P2SH-P2WPKH") == 0) {
        uint8_t redeem_script[22] = {0x00, 0x14};
        memcpy(redeem_script + 2, hash, RIPEMD160_DIGEST_LENGTH);
        uint8_t redeem_hash[RIPEMD160_DIGEST_LENGTH] = {0};
        hash160(redeem_script, 22, redeem_hash);
        if (base58check_encode(0x05, redeem_hash, address, 100) != 0) {
            fprintf(stderr, "Error: P2SH-P2WPKH 地址生成失败。\n"); free(address); return NULL;
        }
    } else if (strcmp(address_type, "BECH32") == 0) { // P2WPKH (SegWit v0)
        if (segwit_addr_encode(address, "bc", 0, hash, RIPEMD160_DIGEST_LENGTH) != 1) {
            fprintf(stderr, "Error: BECH32 (P2WPKH) 地址生成失败。\n"); free(address); return NULL;
        }
    } else if (strcmp(address_type, "BECH32M") == 0) { // SegWit v1 (e.g., P2TR, but here using 20-byte hash)
        if (segwit_addr_encode(address, "bc", 1, hash, RIPEMD160_DIGEST_LENGTH) != 1) {
            fprintf(stderr, "Error: BECH32M (witver 1, 20-byte prog) 地址生成失败。\n"); free(address); return NULL;
        }
    } else if (strcmp(address_type, "P2WSH_NON_STANDARD") == 0) { // 更名以示区别
        // 此处 P2WSH 的 witness program 是 SHA256(Input_Hash160)。
        // 这通常不是标准的 P2WSH 用法，因为 Input_Hash160 不是一个脚本。
        uint8_t sha_of_hash[SHA256_BLOCK_SIZE] = {0};
        sha256(hash, RIPEMD160_DIGEST_LENGTH, sha_of_hash);
        if (segwit_addr_encode(address, "bc", 0, sha_of_hash, SHA256_BLOCK_SIZE) != 1) {
            fprintf(stderr, "Error: P2WSH (SHA256 of input hash) 地址生成失败。\n"); free(address); return NULL;
        }
    } else if (strcmp(address_type, "P2WSH-P2WPKH") == 0) {
        uint8_t p2wpkh_redeem_script[22] = {0x00, 0x14};
        memcpy(p2wpkh_redeem_script + 2, hash, RIPEMD160_DIGEST_LENGTH);
        uint8_t p2wsh_program[SHA256_BLOCK_SIZE] = {0};
        sha256(p2wpkh_redeem_script, 22, p2wsh_program);
        if (segwit_addr_encode(address, "bc", 0, p2wsh_program, SHA256_BLOCK_SIZE) != 1) {
            fprintf(stderr, "Error: P2WSH (from P2WPKH script) 地址生成失败。\n"); free(address); return NULL;
        }
    } else {
        free(address);
        fprintf(stderr, "Error: 不支持的地址类型: %s\n", address_type);
        return NULL;
    }
    return address;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <Hash160 (40 hex characters)>\n", argv[0]);
        return 1;
    }

    char *hash_hex = argv[1];
    if (strlen(hash_hex) != 40) {
        fprintf(stderr, "Error: 输入的 Hash160 长度必须为 40 个十六进制字符。\n");
        return 1;
    }

    printf("Input Hash160: %s\n", hash_hex);
    printf("\n=== Generated Addresses ===\n");

    char *addr;

    addr = hash_to_address(hash_hex, "P2PKH");
    if (addr != NULL) { printf("P2PKH:                    %s\n", addr); free(addr); }

//    addr = hash_to_address(hash_hex, "P2SH");
//    if (addr != NULL) { printf("P2SH:                     %s\n", addr); free(addr); }

    addr = hash_to_address(hash_hex, "P2SH-P2WPKH");
    if (addr != NULL) { printf("P2SH-P2WPKH:              %s\n", addr); free(addr); }

    addr = hash_to_address(hash_hex, "BECH32"); // P2WPKH
    if (addr != NULL) { printf("Bech32 (P2WPKH):          %s\n", addr); free(addr); }

//    addr = hash_to_address(hash_hex, "BECH32M"); // SegWit v1, using 20-byte program from input hash
//    if (addr != NULL) { printf("Bech32m (v1, 20B prog):   %s\n", addr); free(addr); }

    // 对于 P2WSH 的说明：
    // P2WSH (標準) 的 witness program 是 SHA256(redeemScript)。
    // 下面的 "P2WSH_NON_STANDARD" 是直接对输入的 Hash160 进行 SHA256 得到的 witness program。
    // 这通常不是一个有实际用途的 P2WSH 地址，因为其对应的 "redeemScript" 就是输入的 Hash160，而不是一个有效的脚本。
    
//    addr = hash_to_address(hash_hex, "P2WSH_NON_STANDARD");
//    if (addr != NULL) { printf("P2WSH (non-std*, prog=SHA256(input_H160)): %s\n", addr); free(addr); }
    // * non-standard: witness program is SHA256 of the input Hash160, not SHA256 of a redeem script.

    addr = hash_to_address(hash_hex, "P2WSH-P2WPKH"); // P2WSH with program = SHA256(0014{input_hash160})
    if (addr != NULL) { printf("P2WSH (from P2WPKH script):%s\n", addr); free(addr); }

    return 0;
}
