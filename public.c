#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <gmp.h>

#include "sha256/sha256.h"
#include "ripemd160/ripemd160.h"
#include "base58/base58.h"
#include "bech32/bech32.h"
#include "customutil/customutil.h"

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

/* 计算 hash160 (RIPEMD160(SHA256(data))) */
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

/* 根据公钥和地址类型生成地址 */
char *public_key_to_address(const char *public_key_hex, const char *address_type) {
    uint8_t pub_bin[100] = {0}; // 假设公钥最大长度不超过 100 字节
    size_t pub_bin_len = strlen(public_key_hex) / 2;
    if (hex2bin(public_key_hex, pub_bin, pub_bin_len) != 0) {
        fprintf(stderr, "Error: Invalid public key hex.\n");
        return NULL;
    }
    
    uint8_t hash_160[20] = {0};
    hash160(pub_bin, pub_bin_len, hash_160);
    
    char *address = (char *)malloc(100 * sizeof(char));
    if (address == NULL) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        return NULL;
    }
        
    if (strcmp(address_type, "P2PKH") == 0) {
      if (base58check_encode(0x00, hash_160, address, 100) != 0) {
        free(address);
        return NULL;
      }
    } else if (strcmp(address_type, "P2SH") == 0) {
      if (base58check_encode(0x05, hash_160, address, 100) != 0) {
        free(address);
        return NULL;
      }
    } else if (strcmp(address_type, "BECH32") == 0) {
        if(segwit_addr_encode(address, "bc", 0, hash_160, 20) != 1)
        {
          free(address);
           return NULL;
        }
    }
     else if (strcmp(address_type, "BECH32M") == 0) {
        if(segwit_addr_encode(address, "bc", 1, hash_160, 20) != 1)
        {
          free(address);
          return NULL;
        }
     }
    else if(strcmp(address_type, "P2SH-P2WPKH") == 0){
        // P2SH wrapped P2WPKH: redeem script 为 0014<20字节公钥哈希>
        uint8_t redeem_script[22] = {0x00, 0x14};
        memcpy(redeem_script + 2, hash_160, 20);
        uint8_t redeem_hash160[20] = {0};
        hash160(redeem_script, 22, redeem_hash160);
       if (base58check_encode(0x05, redeem_hash160, address, 100) != 0) {
            free(address);
            return NULL;
        }
    }
    else if (strcmp(address_type, "P2WSH") == 0){
          // P2WSH: 使用 SHA256 计算 script hash，地址为 bech32 (witness version 0)
        uint8_t sha[32];
        sha256(pub_bin, pub_bin_len, sha);
      if(segwit_addr_encode(address, "bc", 0, sha, 32) != 1)
       {
          free(address);
           return NULL;
       }
    }
    else if (strcmp(address_type, "P2WSH-P2WPKH") == 0) {
        // P2WSH wrapped P2WPKH: redeem script 为 0014<20字节公钥哈希>，script hash = SHA256(redeem_script)
         uint8_t redeem_script[22] = {0x00, 0x14};
        memcpy(redeem_script + 2, hash_160, 20);
         uint8_t sha[32];
        sha256(redeem_script, 22, sha);
       if(segwit_addr_encode(address, "bc", 0, sha, 32) != 1)
       {
           free(address);
          return NULL;
       }
    } else {
        free(address);
        fprintf(stderr, "Error: Invalid address type.\n");
        return NULL;
    }
   return address;
}

/* 
 * 从压缩公钥恢复非压缩公钥 
 * 输入：压缩公钥 Hex (66字符，前缀 02 或 03)
 * 输出：动态分配的非压缩公钥 Hex (130字符，前缀 04)
 */
char *decompress_public_key(const char* comp_hex) {
    if (strlen(comp_hex) != 66) {
        fprintf(stderr, "Invalid compressed pubkey length.\n");
        return NULL;
    }
    char prefix[3] = {0};
    strncpy(prefix, comp_hex, 2);
    if (strcmp(prefix, "02") != 0 && strcmp(prefix, "03") != 0) {
        fprintf(stderr, "Invalid compressed pubkey prefix.\n");
        return NULL;
    }
    char x_hex[65] = {0};
    strncpy(x_hex, comp_hex + 2, 64);

    mpz_t x, y, rhs, p, exp;
    mpz_inits(x, y, rhs, p, exp, NULL);
    if(mpz_set_str(x, x_hex, 16) != 0){
        fprintf(stderr, "Error converting x coordinate.\n");
        mpz_clears(x, y, rhs, p, exp, NULL);
        return NULL;
    }
    // p = secp256k1 素数
    mpz_set_str(p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    // 计算 rhs = x^3 + 7 (mod p)
    mpz_powm_ui(rhs, x, 3, p);
    mpz_add_ui(rhs, rhs, 7);
    mpz_mod(rhs, rhs, p);
    // 计算 exp = (p + 1) / 4
    mpz_add_ui(exp, p, 1);
    mpz_fdiv_q_ui(exp, exp, 4);
    // 计算 candidate y = rhs^exp mod p
    mpz_powm(y, rhs, exp, p);
    // 检查 y 的奇偶性是否符合压缩公钥前缀
    int y_parity = mpz_tstbit(y, 0); // 0表示偶，1表示奇
    int prefix_parity = (strcmp(prefix, "03") == 0);
    if ((y_parity == 1 && !prefix_parity) || (y_parity == 0 && prefix_parity)) {
        mpz_sub(y, p, y);
    }
    
    // 转换 x 和 y 为固定 64 位的 hex 字符串（不足前面补 0）
    char x_str[65] = {0}, y_str[65] = {0};
    mpz_get_str(x_str, 16, x);
    mpz_get_str(y_str, 16, y);
    char x_fixed[65] = {0}, y_fixed[65] = {0};
    int pad_x = 64 - strlen(x_str);
    int pad_y = 64 - strlen(y_str);
    memset(x_fixed, '0', pad_x);
    strcpy(x_fixed + pad_x, x_str);
    memset(y_fixed, '0', pad_y);
    strcpy(y_fixed + pad_y, y_str);
    
    // 组装非压缩公钥: "04" + x_fixed + y_fixed
    char *uncomp_hex = malloc(2 + 64 + 64 + 1);
    if (uncomp_hex == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        mpz_clears(x, y, rhs, p, exp, NULL);
        return NULL;
    }
    sprintf(uncomp_hex, "04%s%s", x_fixed, y_fixed);
    
    mpz_clears(x, y, rhs, p, exp, NULL);
    return uncomp_hex;
}

/* 
 * 从非压缩公钥生成压缩公钥 
 * 输入：非压缩公钥 Hex (130字符，前缀 04)
 * 输出：动态分配的压缩公钥 Hex (66字符，前缀 02 或 03)
 */
char *compress_public_key(const char* uncomp_hex) {
    if (strlen(uncomp_hex) != 130) {
        fprintf(stderr, "Invalid uncompressed pubkey length.\n");
        return NULL;
    }
    if (strncmp(uncomp_hex, "04", 2) != 0) {
        fprintf(stderr, "Invalid uncompressed pubkey prefix.\n");
        return NULL;
    }
    char x_hex[65] = {0};
    char y_hex[65] = {0};
    strncpy(x_hex, uncomp_hex + 2, 64);
    strncpy(y_hex, uncomp_hex + 66, 64);
    
    mpz_t y;
    mpz_init_set_str(y, y_hex, 16);
    int y_parity = mpz_tstbit(y, 0); // 0: even, 1: odd
    mpz_clear(y);
    
    char *comp_hex = malloc(2 + 64 + 1);
    if (comp_hex == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return NULL;
    }
    sprintf(comp_hex, "%s%s", (y_parity == 0 ? "02" : "03"), x_hex);
    return comp_hex;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <Public Key (Hex)>\n", argv[0]);
        return 1;
    }
    
    char *input_key = argv[1];
    size_t len = strlen(input_key);
    char *comp_pub = NULL;
    char *uncomp_pub = NULL;
    
    if (len == 66) {
        // 输入为压缩格式，解压得到非压缩格式
        comp_pub = strdup(input_key);
        uncomp_pub = decompress_public_key(input_key);
        if (uncomp_pub == NULL) {
            fprintf(stderr, "Error: 解压缩公钥失败\n");
            free(comp_pub);
            return 1;
        }
    } else if (len == 130) {
        // 输入为非压缩格式，压缩生成压缩格式
        uncomp_pub = strdup(input_key);
        comp_pub = compress_public_key(input_key);
        if (comp_pub == NULL) {
            fprintf(stderr, "Error: 压缩公钥失败\n");
            free(uncomp_pub);
            return 1;
        }
    } else {
        fprintf(stderr, "无效的公钥长度，请输入压缩格式（66字符）或非压缩格式（130字符）的公钥 Hex\n");
        return 1;
    }
    
    printf("Compressed Public Key:   %s\n", comp_pub);
    printf("Uncompressed Public Key: %s\n", uncomp_pub);
    
    printf("\n=== Addresses Generated Using Compressed Public Key ===\n");
    char *addr;
    
    addr = public_key_to_address(comp_pub, "P2PKH");
    if (addr) { printf("P2PKH:       %s\n", addr); free(addr); }
    
    addr = public_key_to_address(comp_pub, "P2SH");
    if (addr) { printf("P2SH:        %s\n", addr); free(addr); }
    
    addr = public_key_to_address(comp_pub, "P2SH-P2WPKH");
    if (addr) { printf("P2SH-P2WPKH: %s\n", addr); free(addr); }
    
    addr = public_key_to_address(comp_pub, "BECH32");
    if (addr) { printf("Bech32:      %s\n", addr); free(addr); }
    
    addr = public_key_to_address(comp_pub, "BECH32M");
    if (addr) { printf("Bech32m:     %s\n", addr); free(addr); }
    
    addr = public_key_to_address(comp_pub, "P2WSH");
    if (addr) { printf("P2WSH:       %s\n", addr); free(addr); }
    
    addr = public_key_to_address(comp_pub, "P2WSH-P2WPKH");
    if (addr) { printf("P2WSH-P2WPKH:%s\n", addr); free(addr); }
    
    printf("\n=== Addresses Generated Using Uncompressed Public Key ===\n");
    
    addr = public_key_to_address(uncomp_pub, "P2PKH");
    if (addr) { printf("P2PKH:       %s\n", addr); free(addr); }
    
    addr = public_key_to_address(uncomp_pub, "P2SH");
    if (addr) { printf("P2SH:        %s\n", addr); free(addr); }
    
    addr = public_key_to_address(uncomp_pub, "P2SH-P2WPKH");
    if (addr) { printf("P2SH-P2WPKH: %s\n", addr); free(addr); }
    
    addr = public_key_to_address(uncomp_pub, "BECH32");
    if (addr) { printf("Bech32:      %s\n", addr); free(addr); }
    
    addr = public_key_to_address(uncomp_pub, "BECH32M");
    if (addr) { printf("Bech32m:     %s\n", addr); free(addr); }
    
    addr = public_key_to_address(uncomp_pub, "P2WSH");
    if (addr) { printf("P2WSH:       %s\n", addr); free(addr); }
    
    addr = public_key_to_address(uncomp_pub, "P2WSH-P2WPKH");
    if (addr) { printf("P2WSH-P2WPKH:%s\n", addr); free(addr); }
    
    free(comp_pub);
    free(uncomp_pub);
    
    return 0;
}

