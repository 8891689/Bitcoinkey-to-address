/*🟑 author：github.com/8891689 🟑 */
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
    if (hex_len != bin_len * 2)
        return -1;
    for (size_t i = 0; i < bin_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%02x", &byte) != 1)
            return -1;
        bin[i] = (uint8_t)byte;
    }
    return 0;
}

/* 计算 hash160 = RIPEMD160(SHA256(data)) */
void hash160(const uint8_t *data, size_t data_len, uint8_t *out) {
    uint8_t sha[32];
    sha256(data, data_len, sha);
    RMD160Data(sha, 32, out);
}

/* 根据版本字节和 20 字节数据生成 Base58Check 地址 */
int base58check_encode(uint8_t version, const uint8_t *hash20, char *address, size_t addr_len) {
    uint8_t payload[21];
    payload[0] = version;
    memcpy(payload + 1, hash20, 20);
    uint8_t hash1[32], hash2[32];
    sha256(payload, 21, hash1);
    sha256(hash1, 32, hash2);
    uint8_t full[25];
    memcpy(full, payload, 21);
    memcpy(full + 21, hash2, 4);
    size_t encoded_len = addr_len;
    if (!b58enc(address, &encoded_len, full, 25))
         return -1;
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
    uint8_t hash[20] = {0};
    if (hex2bin(hash_hex, hash, 20) != 0) {
        fprintf(stderr, "Error: 无效的 Hash160 十六进制字符串。\n");
        return NULL;
    }
    
    char *address = (char *)malloc(100 * sizeof(char));
    if (address == NULL) {
        fprintf(stderr, "Error: 内存分配失败。\n");
        return NULL;
    }
    
    if (strcmp(address_type, "P2PKH") == 0) {
        if (base58check_encode(0x00, hash, address, 100) != 0) {
            free(address);
            return NULL;
        }
    } else if (strcmp(address_type, "P2SH") == 0) {
        if (base58check_encode(0x05, hash, address, 100) != 0) {
            free(address);
            return NULL;
        }
    } else if (strcmp(address_type, "P2SH-P2WPKH") == 0) {
        // 构造 redeem script: 0x00, 0x14 + 20 字节 hash
        uint8_t redeem_script[22] = {0x00, 0x14};
        memcpy(redeem_script + 2, hash, 20);
        uint8_t redeem_hash[20] = {0};
        hash160(redeem_script, 22, redeem_hash);
        if (base58check_encode(0x05, redeem_hash, address, 100) != 0) {
            free(address);
            return NULL;
        }
    } else if (strcmp(address_type, "BECH32") == 0) {
        if (segwit_addr_encode(address, "bc", 0, hash, 20) != 1) {
            free(address);
            return NULL;
        }
    } else if (strcmp(address_type, "BECH32M") == 0) {
        if (segwit_addr_encode(address, "bc", 1, hash, 20) != 1) {
            free(address);
            return NULL;
        }
    } else if (strcmp(address_type, "P2WSH") == 0) {
        // 对输入的 hash 做 SHA256，得到 32 字节数据作为 witness program
        uint8_t sha[32] = {0};
        sha256(hash, 20, sha);
        if (segwit_addr_encode(address, "bc", 0, sha, 32) != 1) {
            free(address);
            return NULL;
        }
    } else if (strcmp(address_type, "P2WSH-P2WPKH") == 0) {
        // 构造 redeem script: 0x00, 0x14 + hash，再对 redeem script 做 SHA256
        uint8_t redeem_script[22] = {0x00, 0x14};
        memcpy(redeem_script + 2, hash, 20);
        uint8_t sha[32] = {0};
        sha256(redeem_script, 22, sha);
        if (segwit_addr_encode(address, "bc", 0, sha, 32) != 1) {
            free(address);
            return NULL;
        }
    } else {
        free(address);
        fprintf(stderr, "Error: 不支持的地址类型。\n");
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
    if (addr != NULL) { printf("P2PKH:        %s\n", addr); free(addr); }
    
    addr = hash_to_address(hash_hex, "P2SH");
    if (addr != NULL) { printf("P2SH:         %s\n", addr); free(addr); }
    
    addr = hash_to_address(hash_hex, "P2SH-P2WPKH");
    if (addr != NULL) { printf("P2SH-P2WPKH:  %s\n", addr); free(addr); }
    
    addr = hash_to_address(hash_hex, "BECH32");
    if (addr != NULL) { printf("Bech32:       %s\n", addr); free(addr); }
    
    addr = hash_to_address(hash_hex, "BECH32M");
    if (addr != NULL) { printf("Bech32m:      %s\n", addr); free(addr); }
    
    addr = hash_to_address(hash_hex, "P2WSH");
    if (addr != NULL) { printf("P2WSH:        %s\n", addr); free(addr); }
    
    addr = hash_to_address(hash_hex, "P2WSH-P2WPKH");
    if (addr != NULL) { printf("P2WSH-P2WPKH: %s\n", addr); free(addr); }
    
    return 0;
}

