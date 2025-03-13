/*🟑 author：github.com/8891689 🟑 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "ecc/ecc.h"
#include "sha256/sha256.h"
#include "ripemd160/ripemd160.h"
#include "base58/base58.h"
#include "bech32/bech32.h"
#include "customutil/customutil.h"

/* secp256k1 椭圆曲线参数 */
const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

/* 辅助函数声明 */
int hex2bin(const char *hex, uint8_t *bin, size_t bin_len);
int wif_to_private_key(const char *wif, char *priv_hex, size_t hex_len, bool *compressed);
int private_key_to_wif(const char *priv_hex, bool compressed, char *wif, size_t wif_len);
void hash160(const uint8_t *data, size_t data_len, uint8_t *out);
int base58check_encode(uint8_t version, const uint8_t *hash20, char *address, size_t addr_len);

/* 新增函数声明 */
char *public_key_to_address(const char *public_key_hex, const char *address_type);


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

/* 将 WIF 解码为私钥的 16 进制字符串，并判断是否为压缩格式 */
int wif_to_private_key(const char *wif, char *priv_hex, size_t hex_len, bool *compressed) {
    size_t decoded_len = 100;
    uint8_t decoded[100] = {0};

    if (!b58tobin(decoded, &decoded_len, wif, strlen(wif)))
        return -1;

    /* 解码后长度应为 37 字节（非压缩）或 38 字节（压缩） */
    if (decoded_len == 37)
        *compressed = false;
    else if (decoded_len == 38)
        *compressed = true;
    else
        return -1;

    /* 检查版本字节：应为 0x80 */
    if (decoded[0] != 0x80)
        return -1;

    /* 校验 checksum：对前 decoded_len-4 字节进行双 SHA256 */
    uint8_t hash1[32], hash2[32];
    sha256(decoded, decoded_len - 4, hash1);
    sha256(hash1, 32, hash2);
    if (memcmp(hash2, decoded + decoded_len - 4, 4) != 0)
        return -1;

    /* 私钥位于 decoded[1..32] */
    if (hex_len < 65)
        return -1;
    for (int i = 0; i < 32; i++) {
        sprintf(priv_hex + i * 2, "%02x", decoded[1 + i]);
    }
    priv_hex[64] = '\0';
    return 0;
}

/* 将 32 字节私钥（Hex）转换为 WIF 格式 */
int private_key_to_wif(const char *priv_hex, bool compressed, char *wif, size_t wif_len) {
    uint8_t priv_bin[32];
    if (hex2bin(priv_hex, priv_bin, 32) != 0)
        return -1;
    uint8_t payload[34];
    payload[0] = 0x80;
    memcpy(payload + 1, priv_bin, 32);
    size_t payload_len = 33;
    if (compressed) {
        payload[33] = 0x01;
        payload_len = 34;
    }
    uint8_t hash1[32], hash2[32];
    sha256(payload, payload_len, hash1);
    sha256(hash1, 32, hash2);
    uint8_t full[38];
    memcpy(full, payload, payload_len);
    memcpy(full + payload_len, hash2, 4);
    size_t full_len = payload_len + 4;
    size_t encoded_len = wif_len;
    if (!b58enc(wif, &encoded_len, full, full_len))
        return -1;
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


/* 新增函数：根据公钥和地址类型生成地址 */
char *public_key_to_address(const char *public_key_hex, const char *address_type) {
    uint8_t pub_bin[100] = {0}; // 假设公钥最大长度为 100 bytes
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
        // P2SH wrapped P2WPKH: script is hash160(0014<20 byte key hash>), address is base58(script, 0x05 version)
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
          // P2WSH: script hash is hash256(script), address is bech32(witness_version = 0, script_hash)
        uint8_t sha[32];
        sha256(pub_bin, pub_bin_len, sha);
      if(segwit_addr_encode(address, "bc", 0, sha, 32) != 1)
       {
          free(address);
           return NULL;
       }
    }
    else if (strcmp(address_type, "P2WSH-P2WPKH") == 0) {
        // P2WSH wrapped P2WPKH: redeem_script is 0014<20byte public key hash>, script_hash = sha256(script)
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

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <Private Key (Hex or WIF)>\n", argv[0]);
        return 1;
    }

    /* 初始化 secp256k1 参数 */
    EllipticCurve EC;
    Point G;
    mpz_inits(EC.p, EC.a, EC.b, EC.n, NULL);
    mpz_set_str(EC.p, EC_constant_P, 16);
    mpz_set_ui(EC.a, 0);    // secp256k1: a = 0
    mpz_set_ui(EC.b, 7);    // secp256k1: b = 7
    mpz_set_str(EC.n, EC_constant_N, 16);

    point_init(&G);
    mpz_set_str(G.x, EC_constant_Gx, 16);
    mpz_set_str(G.y, EC_constant_Gy, 16);
    G.infinity = 0;

    char *input_key = argv[1];
    bool is_wif = false, compressed_flag = false;
    char priv_hex[65] = {0};
    char wif[100] = {0};

    /* 判断输入格式：如果首字符为 '5'、'K' 或 'L' 则认为是 WIF 格式 */
    if (input_key[0] == '5' || input_key[0] == 'K' || input_key[0] == 'L') {
        is_wif = true;
        if (wif_to_private_key(input_key, priv_hex, sizeof(priv_hex), &compressed_flag) != 0) {
            fprintf(stderr, "WIF 解码失败\n");
            return 1;
        }
        printf("WIF Private Key: %s\n", input_key);
        printf("Raw Private Key (Hex): %s\n", priv_hex);
    } else {
        // 当输入长度不足 64 时左侧补零
        if (strlen(input_key) < 64) {
            char padded[65] = {0};
            int pad = 64 - strlen(input_key);
            memset(padded, '0', pad);
            strcpy(padded + pad, input_key);
            strcpy(priv_hex, padded);
        } else if (strlen(input_key) == 64) {
            strcpy(priv_hex, input_key);
        } else {
            fprintf(stderr, "无效的私钥 hex 长度，应为 64 字符\n");
            return 1;
        }
        
        char wif_compressed[100] = {0};
        char wif_uncompressed[100] = {0};

        if (private_key_to_wif(priv_hex, true, wif_compressed, sizeof(wif_compressed)) != 0) {
            fprintf(stderr, "私钥转换为压缩 WIF 失败\n");
            return 1;
        }
        if (private_key_to_wif(priv_hex, false, wif_uncompressed, sizeof(wif_uncompressed)) != 0) {
            fprintf(stderr, "私钥转换为非压缩 WIF 失败\n");
            return 1;
        }

        printf("WIF Private Key (Compressed): %s\n", wif_compressed);
        printf("WIF Private Key (Uncompressed): %s\n", wif_uncompressed);
    }

    
    /* 由私钥计算公钥 */
    mpz_t priv;
    mpz_init_set_str(priv, priv_hex, 16);
    Point pub;
    point_init(&pub);
    /* 调用标量乘法： pub = priv * G */
    scalar_multiplication(&EC, &G, &pub, priv);
    
    char pub_hex_comp[67] = {0};
    char pub_hex_uncomp[131] = {0};
    /* 生成公钥字符串（由 customutil 模块提供） */
    generate_strpublickey(&pub, true, pub_hex_comp);    // 生成压缩格式
    generate_strpublickey(&pub, false, pub_hex_uncomp);   // 生成非压缩格式
    printf("Compressed Public Key: %s\n", pub_hex_comp);
    printf("Uncompressed Public Key: %s\n", pub_hex_uncomp);

    printf("=== Addresses Generated from Compressed Public Key ===\n");
    char *p2pkh_address_compressed = public_key_to_address(pub_hex_comp, "P2PKH");
    if (p2pkh_address_compressed != NULL)
      printf("P2PKH (Starts with 1) Address (Compressed): %s\n", p2pkh_address_compressed);
      free(p2pkh_address_compressed);

    char *p2sh_address_compressed = public_key_to_address(pub_hex_comp, "P2SH");
    if (p2sh_address_compressed != NULL)
      //printf("P2SH (Starts with 3) Address (Compressed): %s (P2SH => P2PKH)\n", p2sh_address_compressed);
    free(p2sh_address_compressed);
    
    char *p2sh_p2wpkh_address_compressed = public_key_to_address(pub_hex_comp, "P2SH-P2WPKH");
        if (p2sh_p2wpkh_address_compressed != NULL)
         printf("P2SH (Starts with 3) Address (Compressed): %s (P2SH => P2WPKH)\n", p2sh_p2wpkh_address_compressed);
    free(p2sh_p2wpkh_address_compressed);

    char *bech32_address_compressed = public_key_to_address(pub_hex_comp, "BECH32");
        if (bech32_address_compressed != NULL)
      printf("Bech32 (Starts with bc1) Address (Compressed): %s\n", bech32_address_compressed);
    free(bech32_address_compressed);

    char *bech32m_address_compressed = public_key_to_address(pub_hex_comp, "BECH32M");
        if (bech32m_address_compressed != NULL)
     // printf("Bech32m (Starts with bc1p) Address (Compressed): %s\n", bech32m_address_compressed);
    free(bech32m_address_compressed);

    char *p2wsh_address_compressed = public_key_to_address(pub_hex_comp, "P2WSH");
    if (p2wsh_address_compressed != NULL)
        //printf("P2WSH (Starts with bc1) Address (Compressed): %s (P2WSH => P2PKH)\n", p2wsh_address_compressed);
     free(p2wsh_address_compressed);
     
    char *p2wsh_p2wpkh_address_compressed = public_key_to_address(pub_hex_comp, "P2WSH-P2WPKH");
    if (p2wsh_p2wpkh_address_compressed != NULL)
        //printf("P2WSH (Starts with bc1) Address (Compressed): %s (P2WSH => P2WPKH)\n", p2wsh_p2wpkh_address_compressed);
    free(p2wsh_p2wpkh_address_compressed);


    printf("=== Addresses Generated from Uncompressed Public Key ===\n");
    char *p2pkh_address_uncompressed = public_key_to_address(pub_hex_uncomp, "P2PKH");
    if (p2pkh_address_uncompressed != NULL)
      printf("P2PKH (Starts with 1) Address (Uncompressed): %s\n", p2pkh_address_uncompressed);
    free(p2pkh_address_uncompressed);

    char *p2sh_address_uncompressed = public_key_to_address(pub_hex_uncomp, "P2SH");
    if (p2sh_address_uncompressed != NULL)
       //printf("P2SH (Starts with 3) Address (Uncompressed): %s (P2SH => P2PKH)\n", p2sh_address_uncompressed);
    free(p2sh_address_uncompressed);

   char *p2sh_p2wpkh_address_uncompressed = public_key_to_address(pub_hex_uncomp, "P2SH-P2WPKH");
       if (p2sh_p2wpkh_address_uncompressed != NULL)
        printf("P2SH (Starts with 3) Address (Uncompressed): %s (P2SH => P2WPKH)\n", p2sh_p2wpkh_address_uncompressed);
    free(p2sh_p2wpkh_address_uncompressed);
    
    char *bech32_address_uncompressed = public_key_to_address(pub_hex_uncomp, "BECH32");
    if (bech32_address_uncompressed != NULL)
      printf("Bech32 (Starts with bc1) Address (Uncompressed): %s\n", bech32_address_uncompressed);
    free(bech32_address_uncompressed);

    char *bech32m_address_uncompressed = public_key_to_address(pub_hex_uncomp, "BECH32M");
      if (bech32m_address_uncompressed != NULL)
      //printf("Bech32m (Starts with bc1p) Address (Uncompressed): %s\n", bech32m_address_uncompressed);
    free(bech32m_address_uncompressed);
    
    char *p2wsh_address_uncompressed = public_key_to_address(pub_hex_uncomp, "P2WSH");
        if (p2wsh_address_uncompressed != NULL)
      //printf("P2WSH (Starts with bc1) Address (Uncompressed): %s (P2WSH => P2PKH)\n", p2wsh_address_uncompressed);
    free(p2wsh_address_uncompressed);
    
    char *p2wsh_p2wpkh_address_uncompressed = public_key_to_address(pub_hex_uncomp, "P2WSH-P2WPKH");
        if (p2wsh_p2wpkh_address_uncompressed != NULL)
      //printf("P2WSH (Starts with bc1) Address (Uncompressed): %s (P2WSH => P2WPKH)\n", p2wsh_p2wpkh_address_uncompressed);
   free(p2wsh_p2wpkh_address_uncompressed);

    /* 释放 GMP 与 ECC 资源 */
    mpz_clear(priv);
    point_clear(&pub);
    point_clear(&G);
    mpz_clear(EC.p);
    mpz_clear(EC.a);
    mpz_clear(EC.b);
    mpz_clear(EC.n);
    
    return 0;
}
