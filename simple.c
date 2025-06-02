/*🟑 author：github.com/8891689 
     gcc -O3 -o skey simple.c sha256.c base58.c bech32.c ripemd160.c secp256k1.c
    🟑 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

#include "secp256k1/secp256k1.h"
#include "sha256/sha256.h"
#include "ripemd160/ripemd160.h"
#include "base58/base58.h"
#include "bech32/bech32.h"

/* 辅助函数声明 */
int hex2bin(const char *hex, uint8_t *bin, size_t bin_len);
int wif_to_private_key(const char *wif, char *priv_hex, size_t hex_len, bool *compressed);
int private_key_to_wif(const char *priv_hex, bool compressed, char *wif, size_t wif_len);
void hash160(const uint8_t *data, size_t data_len, uint8_t *out);
int base58check_encode(uint8_t version, const uint8_t *hash20, char *address, size_t addr_len);

/* 函数声明 */
char *public_key_to_address(const char *public_key_hex, const char *address_type);


/* 将 hex 字符串转换为二进制数据 */
int hex2bin(const char *hex, uint8_t *bin, size_t bin_len) {
    size_t hex_len_actual = strlen(hex);
    const char *hex_start = hex;

    if (hex_len_actual >= 2 && hex_start[0] == '0' && (hex_start[1] == 'x' || hex_start[1] == 'X')) {
        hex_start += 2;
        hex_len_actual -= 2;
    }

    if (hex_len_actual != bin_len * 2) {
        // fprintf(stderr, "hex2bin error: hex_len_actual (%zu) != bin_len * 2 (%zu) for hex: %s\n", hex_len_actual, bin_len*2, hex);
        return -1;
    }
    for (size_t i = 0; i < bin_len; i++) {
        unsigned int byte;
        if (sscanf(hex_start + 2 * i, "%02x", &byte) != 1) {
            // fprintf(stderr, "hex2bin sscanf error for hex: %s, part: %c%c\n", hex, hex_start[2*i], hex_start[2*i+1]);
            return -1;
        }
        bin[i] = (uint8_t)byte;
    }
    return 0;
}

/* 将 WIF 解码为私钥的 16 进制字符串，并判断是否为压缩格式 */
int wif_to_private_key(const char *wif, char *priv_hex, size_t hex_len, bool *compressed) {
    size_t decoded_len_inout = 100; 
    uint8_t decoded[100] = {0};

    if (!b58tobin(decoded, &decoded_len_inout, wif, strlen(wif)))
        return -1;
    
    size_t actual_decoded_len = decoded_len_inout; // Use the output length from b58tobin

    if (actual_decoded_len == 37)
        *compressed = false;
    else if (actual_decoded_len == 38)
        *compressed = true;
    else {
        // fprintf(stderr, "WIF decoded length error: expected 37 or 38, got %zu\n", actual_decoded_len);
        return -1;
    }

    if (decoded[0] != 0x80) {
        // fprintf(stderr, "WIF version byte error: expected 0x80, got 0x%02x\n", decoded[0]);
        return -1;
    }
    uint8_t hash1[SHA256_BLOCK_SIZE], hash2[SHA256_BLOCK_SIZE];
    sha256(decoded, actual_decoded_len - 4, hash1);
    sha256(hash1, SHA256_BLOCK_SIZE, hash2);
    if (memcmp(hash2, decoded + actual_decoded_len - 4, 4) != 0) {
        // fprintf(stderr, "WIF checksum error\n");
        return -1;
    }
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
    uint8_t hash1[SHA256_BLOCK_SIZE], hash2[SHA256_BLOCK_SIZE];
    sha256(payload, payload_len, hash1);
    sha256(hash1, SHA256_BLOCK_SIZE, hash2);
    
    uint8_t full[38];
    memcpy(full, payload, payload_len);
    memcpy(full + payload_len, hash2, 4);
    size_t full_len = payload_len + 4;
    
    if (!b58enc(wif, &wif_len, full, full_len)) 
        return -1;
    return 0;
}

/* 计算 hash160 (RIPEMD160(SHA256(data))) */
void hash160(const uint8_t *data, size_t data_len, uint8_t *out) {
    uint8_t sha_output[SHA256_BLOCK_SIZE];
    sha256(data, data_len, sha_output);
    ripemd160(sha_output, SHA256_BLOCK_SIZE, out);
}

/* 根据版本字节和 20 字节数据生成 Base58Check 地址 */
int base58check_encode(uint8_t version, const uint8_t *hash20, char *address, size_t addr_len) {
    uint8_t payload[21];
    payload[0] = version;
    memcpy(payload + 1, hash20, 20);
    
    uint8_t hash1[SHA256_BLOCK_SIZE], hash2[SHA256_BLOCK_SIZE];
    sha256(payload, 21, hash1);
    sha256(hash1, SHA256_BLOCK_SIZE, hash2);
    
    uint8_t full[25];
    memcpy(full, payload, 21);
    memcpy(full + 21, hash2, 4);
    
    if (!b58enc(address, &addr_len, full, 25))
         return -1;
    return 0;
}


/* 根据公钥和地址类型生成地址 */
char *public_key_to_address(const char *public_key_hex, const char *address_type) {
    uint8_t pub_bin[100] = {0}; 
    size_t pub_bin_len = strlen(public_key_hex) / 2;
    if (hex2bin(public_key_hex, pub_bin, pub_bin_len) != 0) {
        fprintf(stderr, "Error: Invalid public key hex for address generation: %s\n", public_key_hex);
        return NULL;
    }
    
    uint8_t hash_160_output[RIPEMD160_DIGEST_LENGTH] = {0};
    hash160(pub_bin, pub_bin_len, hash_160_output);
    
    char *address = (char *)malloc(100 * sizeof(char)); 
    if (address == NULL) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        return NULL;
    }
    memset(address, 0, 100); 
        
    if (strcmp(address_type, "P2PKH") == 0) {
      size_t addr_len_p2pkh = 100;
      if (base58check_encode(0x00, hash_160_output, address, addr_len_p2pkh) != 0) {
        free(address);
        return NULL;
      }
    } else if (strcmp(address_type, "P2SH") == 0) {
      size_t addr_len_p2sh = 100;
      if (base58check_encode(0x05, hash_160_output, address, addr_len_p2sh) != 0) {
        free(address);
        return NULL;
      }
    } else if (strcmp(address_type, "BECH32") == 0) { // P2WPKH
        if(segwit_addr_encode(address, "bc", 0, hash_160_output, RIPEMD160_DIGEST_LENGTH) != 1) 
        {
          free(address);
           return NULL;
        }
    }
     else if (strcmp(address_type, "BECH32M") == 0) { 
        if(segwit_addr_encode(address, "bc", 1, hash_160_output, RIPEMD160_DIGEST_LENGTH) != 1)
        {
          free(address);
          return NULL;
        }
     }
    else if(strcmp(address_type, "P2SH-P2WPKH") == 0){
        uint8_t redeem_script[22] = {0x00, 0x14}; 
        memcpy(redeem_script + 2, hash_160_output, RIPEMD160_DIGEST_LENGTH);
        uint8_t redeem_hash160[RIPEMD160_DIGEST_LENGTH] = {0};
        hash160(redeem_script, 22, redeem_hash160);
        size_t addr_len_p2sh_p2wpkh = 100;
       if (base58check_encode(0x05, redeem_hash160, address, addr_len_p2sh_p2wpkh) != 0) {
            free(address);
            return NULL;
        }
    }
    else if (strcmp(address_type, "P2WSH") == 0){
        // P2WSH: witness program is SHA256 hash of the script.
        // For a P2WSH wrapping a simple pubkey (e.g. <pubkey> OP_CHECKSIG type script),
        // the script itself would be the pubkey.
        uint8_t script_hash[SHA256_BLOCK_SIZE];
        sha256(pub_bin, pub_bin_len, script_hash); 
      // MODIFICATION: Change witver from 0 to 1 for Bech32m (bc1p...)
      if(segwit_addr_encode(address, "bc", 1, script_hash, SHA256_BLOCK_SIZE) != 1)
       {
          free(address);
           return NULL;
       }
    }
    else if (strcmp(address_type, "P2WSH-P2WPKH") == 0) {
        uint8_t p2wpkh_script[22] = {0x00, 0x14};
        memcpy(p2wpkh_script + 2, hash_160_output, RIPEMD160_DIGEST_LENGTH);
        uint8_t script_sha256[SHA256_BLOCK_SIZE];
        sha256(p2wpkh_script, 22, script_sha256);
       if(segwit_addr_encode(address, "bc", 0, script_sha256, SHA256_BLOCK_SIZE) != 1) // This remains witver 0 for bc1q for this specific type
       {
           free(address);
          return NULL;
       }
    } else {
        free(address);
        fprintf(stderr, "Error: Invalid address type: %s\n", address_type);
        return NULL;
    }
   return address;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <Private Key (Hex or WIF)>\n", argv[0]);
        return 1;
    }

    char *input_str = argv[1];
    char processed_input[256];
    strncpy(processed_input, input_str, sizeof(processed_input) - 1);
    processed_input[sizeof(processed_input) - 1] = '\0';

    char *key_data_ptr = processed_input;
    size_t key_data_len = strlen(key_data_ptr);

    bool is_hex_prefix = false;
    if (key_data_len > 2 && key_data_ptr[0] == '0' && (key_data_ptr[1] == 'x' || key_data_ptr[1] == 'X')) {
        key_data_ptr += 2;
        key_data_len -= 2;
        is_hex_prefix = true;
    }

    bool is_wif_input = false; // Renamed from is_wif to avoid confusion
    bool wif_input_compressed_status = false;
    char priv_hex[65] = {0};

    // Try to decode as WIF first
    if (!is_hex_prefix && (key_data_len == 51 || key_data_len == 52) &&
        (key_data_ptr[0] == 'K' || key_data_ptr[0] == 'L' || key_data_ptr[0] == '5')) {
        if (wif_to_private_key(key_data_ptr, priv_hex, sizeof(priv_hex), &wif_input_compressed_status) == 0) {
            is_wif_input = true;
            printf("Input Private Key (WIF): %s\n", key_data_ptr);
            // No need to print "Implies Compressed Public Key" here, as we'll show the other WIF form
        }
    }

    // If not WIF or WIF decoding failed, treat as hex
    if (!is_wif_input) {
        if (key_data_len == 64) {
            bool valid_hex = true;
            for(size_t i=0; i < key_data_len; ++i) {
                if (!isxdigit(key_data_ptr[i])) { valid_hex = false; break; }
            }
            if (!valid_hex) {
                fprintf(stderr, "Error: Input is not a valid 64-char hex string.\n");
                if ((key_data_ptr[0] == 'K' || key_data_ptr[0] == 'L' || key_data_ptr[0] == '5'))
                   fprintf(stderr, "       And it failed to decode as WIF.\n");
                return 1;
            }
            strncpy(priv_hex, key_data_ptr, 64);
            priv_hex[64] = '\0';
        } else if (key_data_len > 0 && key_data_len < 64) {
            bool valid_short_hex = true;
            for(size_t i=0; i < key_data_len; ++i) {
                if (!isxdigit(key_data_ptr[i])) { valid_short_hex = false; break; }
            }
            if (!valid_short_hex) {
                fprintf(stderr, "Error: Input is not a valid short hex string and not WIF.\n");
                return 1;
            }
            int num_padding_zeros = 64 - key_data_len;
            memset(priv_hex, '0', num_padding_zeros);
            strncpy(priv_hex + num_padding_zeros, key_data_ptr, key_data_len);
            priv_hex[64] = '\0';
        } else {
            fprintf(stderr, "Error: Invalid input format. Not WIF and not a valid hex private key (1-64 chars, optionally 0x).\n");
            fprintf(stderr, "       Processed input: %s (length %zu)\n", key_data_ptr, key_data_len);
            return 1;
        }
        printf("Input Private Key (Hex): %s\n", (is_hex_prefix ? argv[1] : key_data_ptr) );
    }

    printf("Private Key (Hex, 32 bytes): %s\n", priv_hex);

    // WIF output logic refined
    if (is_wif_input) {
        // If input was WIF, show the OTHER WIF format
        bool show_compressed_wif = !wif_input_compressed_status;
        char other_wif[100] = {0};
        size_t other_wif_len = sizeof(other_wif);
        if (private_key_to_wif(priv_hex, show_compressed_wif, other_wif, other_wif_len) == 0) {
            if (show_compressed_wif) {
                printf("WIF (Compressed):   %s\n", other_wif);
            } else {
                printf("WIF (Uncompressed): %s\n", other_wif);
            }
        } else {
            fprintf(stderr, "Error: Failed to convert private key to the other WIF format.\n");
        }
    } else {
        // If input was Hex, show both WIF formats
        char wif_uncompressed_out[100] = {0};
        size_t wif_uncomp_len = sizeof(wif_uncompressed_out);
        if (private_key_to_wif(priv_hex, false, wif_uncompressed_out, wif_uncomp_len) == 0) {
             printf("WIF (Uncompressed): %s\n", wif_uncompressed_out);
        } else {
            fprintf(stderr, "Error: Failed to convert private key to uncompressed WIF.\n");
        }

        char wif_compressed_out[100] = {0};
        size_t wif_comp_len = sizeof(wif_compressed_out);
        if (private_key_to_wif(priv_hex, true, wif_compressed_out, wif_comp_len) == 0) {
             printf("WIF (Compressed):   %s\n", wif_compressed_out);
        } else {
            fprintf(stderr, "Error: Failed to convert private key to compressed WIF.\n");
        }
    }


    char pub_hex_comp[67] = {0};
    char pub_hex_uncomp[131] = {0};

    if (strlen(priv_hex) != 64) {
         fprintf(stderr, "Error: Internal - priv_hex invalid before pubkey generation: '%s'\n", priv_hex);
         return 1;
    }
    compute_public_keys(priv_hex, pub_hex_comp, pub_hex_uncomp);

    if (strlen(pub_hex_comp) == 0 || strlen(pub_hex_uncomp) == 0) {
        fprintf(stderr, "Error: Failed to compute public keys from private key: %s\n", priv_hex);
        return 1;
    }

    printf("\nPublic Key (Compressed,   33 bytes): %s\n", pub_hex_comp);
    printf("Public Key (Uncompressed, 65 bytes): %s\n", pub_hex_uncomp);

    char *addr; 

    printf("\n=== Addresses Generated from Compressed Public Key ===\n");
    addr = public_key_to_address(pub_hex_comp, "P2PKH");
    if (addr) { printf("P2PKH:        %s\n", addr); free(addr); }

//    addr = public_key_to_address(pub_hex_comp, "P2SH"); 
//    if (addr) { printf("P2SH:         %s\n", addr); free(addr); }

    addr = public_key_to_address(pub_hex_comp, "P2SH-P2WPKH");
    if (addr) { printf("P2SH-P2WPKH:  %s\n", addr); free(addr); }

    addr = public_key_to_address(pub_hex_comp, "BECH32"); 
    if (addr) { printf("BECH32:       %s\n", addr); free(addr); }

//    addr = public_key_to_address(pub_hex_comp, "BECH32M"); 
//    if (addr) { printf("BECH32M:      %s\n", addr); free(addr); }

//    addr = public_key_to_address(pub_hex_comp, "P2WSH"); 
//    if (addr) { printf("P2WSH:        %s\n", addr); free(addr); }

    addr = public_key_to_address(pub_hex_comp, "P2WSH-P2WPKH"); 
    if (addr) { printf("P2WSH-P2WPKH: %s\n", addr); free(addr); }


    printf("\n=== Addresses Generated from Uncompressed Public Key ===\n");
    addr = public_key_to_address(pub_hex_uncomp, "P2PKH");
    if (addr) { printf("P2PKH:        %s\n", addr); free(addr); }

//    addr = public_key_to_address(pub_hex_uncomp, "P2SH"); 
//    if (addr) { printf("P2SH:         %s\n", addr); free(addr); }

    addr = public_key_to_address(pub_hex_uncomp, "P2SH-P2WPKH");
    if (addr) { printf("P2SH-P2WPKH:  %s (Note: Non-standard)\n", addr); free(addr); }

    addr = public_key_to_address(pub_hex_uncomp, "BECH32"); 
    if (addr) { printf("BECH32:       %s (Note: Non-standard)\n", addr); free(addr); }

//    addr = public_key_to_address(pub_hex_uncomp, "BECH32M"); 
//    if (addr) { printf("BECH32M:      %s (Note: Non-standard)\n", addr); free(addr); }

//    addr = public_key_to_address(pub_hex_uncomp, "P2WSH"); 
//    if (addr) { printf("P2WSH:        %s\n", addr); free(addr); }

    addr = public_key_to_address(pub_hex_uncomp, "P2WSH-P2WPKH"); 
    if (addr) { printf("P2WSH-P2WPKH: %s (Note: Non-standard)\n", addr); free(addr); }

    printf("\n");
    return 0;
}
