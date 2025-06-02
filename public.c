/* Author: github.com/8891689
 * gcc -O3 -o p pubkey.c sha256.c base58.c bech32.c ripemd160.c secp256k1.c
 */
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
void hash160(const uint8_t *data, size_t data_len, uint8_t *out);
int base58check_encode(uint8_t version, const uint8_t *hash20, char *address, size_t addr_len);

// 新增輔助函數：將二進制數據轉換為十六進制字符串 (不變)
void bin2hex(const uint8_t *bin, size_t bin_len, char *hex, size_t hex_len) {
    if (hex_len < bin_len * 2 + 1) {
        if (hex_len > 0) hex[0] = '\0';
        return;
    }
    for (size_t i = 0; i < bin_len; i++) {
        sprintf(hex + i * 2, "%02x", bin[i]);
    }
    hex[bin_len * 2] = '\0';
}

// --- Functions for secp256k1 operations based on your custom library ---
extern void calculate_y_squared_secp256k1(BigInt *y_squared, const BigInt *x);
extern int calculate_mod_sqrt_secp256k1(BigInt *y_root, const BigInt *a);
extern int hex_str_to_ecpoint(const char *pub_hex_str, ECPoint *P); // 声明 hex_str_to_ecpoint

// Gets both compressed and uncompressed formats from an input public key hex string.
int get_both_pubkey_formats_from_input_pubkey_custom(
    const char *input_pubkey_hex,
    char *output_compressed_pubkey_hex,   // Buffer size 67
    char *output_uncompressed_pubkey_hex  // Buffer size 131
) {
    ECPoint point; // Uses ECPoint from your secp256k1.h
    // secp256k1_p is used internally by hex_str_to_ecpoint if needed for mod_sqrt etc.
    if (hex_str_to_ecpoint(input_pubkey_hex, &point) != 0) {
        // Error message would have been printed by hex_str_to_ecpoint
        return -1;
    }

    if (point.infinity) {
        fprintf(stderr, "Error: Parsed public key resulted in point at infinity.\n");
        return -1;
    }

    // Use your library's functions to convert the ECPoint to hex strings
    point_to_compressed_hex(&point, output_compressed_pubkey_hex);
    point_to_uncompressed_hex(&point, output_uncompressed_pubkey_hex);

    // Basic validation of output lengths
    if (strlen(output_compressed_pubkey_hex) != 66) {
        fprintf(stderr, "Error: Generated compressed public key hex has incorrect length (%zu instead of 66). Value: %s\n",
                strlen(output_compressed_pubkey_hex), output_compressed_pubkey_hex);
        // Continue anyway, as uncompressed might still work, but warn.
    }
    if (strlen(output_uncompressed_pubkey_hex) != 130) {
        fprintf(stderr, "Error: Generated uncompressed public key hex has incorrect length (%zu instead of 130). Value: %s\n",
                strlen(output_uncompressed_pubkey_hex), output_uncompressed_pubkey_hex);
        // Continue anyway, but warn.
    }
    // Only return success if at least one format looks plausible length-wise
    if (strlen(output_compressed_pubkey_hex) == 66 || strlen(output_uncompressed_pubkey_hex) == 130) {
       return 0;
    } else {
       return -1; // Neither looked right
    }
}

/* 将 hex 字符串转换为二进制数据 */
int hex2bin(const char *hex, uint8_t *bin, size_t bin_len) {
    size_t hex_len_actual = strlen(hex);
    const char *hex_start = hex;

    if (hex_len_actual >= 2 && hex_start[0] == '0' && (hex_start[1] == 'x' || hex_start[1] == 'X')) {
        hex_start += 2;
        hex_len_actual -= 2;
    }

    if (hex_len_actual != bin_len * 2) {
        if (hex_len_actual > bin_len * 2) return -1; // Hex too long

        // Pad with leading zeros if hex is shorter than bin_len * 2
        size_t padding = bin_len * 2 - hex_len_actual;
        if (padding % 2 != 0) return -1; // Must be even length hex

        memset(bin, 0, padding / 2);
        bin += padding / 2;
        bin_len -= padding / 2;
        hex_start = hex + (strlen(hex) - hex_len_actual); // Adjust start if 0x prefix was skipped
    }


    for (size_t i = 0; i < bin_len; i++) {
        unsigned int byte_val;
        if (sscanf(hex_start + 2 * i, "%02x", &byte_val) != 1) {
            // fprintf(stderr, "hex2bin sscanf error for hex: %s, part: %c%c\n", hex_start, hex_start[2*i], hex_start[2*i+1]);
            return -1;
        }
        bin[i] = (uint8_t)byte_val;
    }
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

/* 根据公钥和地址类型生成地址 (精简版) */
char *public_key_to_address(const char *public_key_hex, const char *address_type) {
    uint8_t pub_bin[65]; // Max 65 bytes for uncompressed pubkey
    size_t pub_bin_expected_len = strlen(public_key_hex) / 2;

    // Validate public key format based on expected hex length and first byte prefix
    if (!((pub_bin_expected_len == 33 && public_key_hex[0] == '0' && (public_key_hex[1] == '2' || public_key_hex[1] == '3')) ||
          (pub_bin_expected_len == 65 && public_key_hex[0] == '0' && public_key_hex[1] == '4'))) {
        fprintf(stderr, "Error(public_key_to_address): Invalid public key hex length/format for address generation. Len: %zu, Hex: %s\n", pub_bin_expected_len, public_key_hex);
        return NULL;
    }

    if (hex2bin(public_key_hex, pub_bin, pub_bin_expected_len) != 0) {
        fprintf(stderr, "Error(public_key_to_address): Invalid public key hex to bin conversion. Hex: %s\n", public_key_hex);
        return NULL;
    }

    uint8_t hash_160_output[RIPEMD160_DIGEST_LENGTH] = {0};
    

    hash160(pub_bin, pub_bin_expected_len, hash_160_output);

    char *address = (char *)malloc(100 * sizeof(char));
    if (address == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for address.\n");
        return NULL;
    }
    memset(address, 0, 100);

    if (strcmp(address_type, "P2PKH") == 0) {
      size_t addr_len_val = 100;
      // Uses HASH160 of input public key (33 or 65 bytes)
      if (base58check_encode(0x00, hash_160_output, address, addr_len_val) != 0) {
        free(address); return NULL;
      }
    } else if (strcmp(address_type, "P2SH-P2WPKH") == 0) {

        uint8_t redeem_script[22] = {0x00, 0x14}; 
        memcpy(redeem_script + 2, hash_160_output, RIPEMD160_DIGEST_LENGTH);
        uint8_t redeem_hash160[RIPEMD160_DIGEST_LENGTH] = {0};
        hash160(redeem_script, 22, redeem_hash160); // HASH160 of the redeem script
        size_t addr_len_val = 100;
       if (base58check_encode(0x05, redeem_hash160, address, addr_len_val) != 0) {
            free(address); return NULL;
        }
    } else if (strcmp(address_type, "BECH32") == 0) { // This implies P2WPKH

        if(segwit_addr_encode(address, "bc", 0, hash_160_output, RIPEMD160_DIGEST_LENGTH) != 1) {
          free(address); return NULL;
        }
    } else if (strcmp(address_type, "P2WSH-P2WPKH") == 0) {

        uint8_t p2wpkh_script[22] = {0x00, 0x14};
        memcpy(p2wpkh_script + 2, hash_160_output, RIPEMD160_DIGEST_LENGTH); // Use HASH160 of input pubkey in the script
        uint8_t script_sha256[SHA256_BLOCK_SIZE];
        sha256(p2wpkh_script, 22, script_sha256); // SHA256 of the witness script
       if(segwit_addr_encode(address, "bc", 0, script_sha256, SHA256_BLOCK_SIZE) != 1) {
           free(address); return NULL;
       }
    } else {
        free(address); // Free if type not supported/matched
        fprintf(stderr, "Error: Unsupported address type: %s\n", address_type);
        return NULL; 
    }
   return address;
}


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <Public Key Hex (Compressed or Uncompressed)>\n", argv[0]);
        return 1;
    }

    char *input_pubkey_hex_str = argv[1];
    char pub_hex_comp[67] = {0};    
    char pub_hex_uncomp[131] = {0}; 

    // Attempt to parse the input hex and get both standard formats
    if (get_both_pubkey_formats_from_input_pubkey_custom(input_pubkey_hex_str, pub_hex_comp, pub_hex_uncomp) != 0) {
        fprintf(stderr, "Failed to parse input public key or derive standard formats.\n");
        size_t input_len = strlen(input_pubkey_hex_str);
        if (input_len == 66 || input_len == 130) {
            fprintf(stderr, "Proceeding with input public key hex for address generation.\n");
            strcpy(pub_hex_comp, (input_len == 66) ? input_pubkey_hex_str : ""); // Only use input if it was compressed
            strcpy(pub_hex_uncomp, (input_len == 130) ? input_pubkey_hex_str : ""); // Only use input if it was uncompressed
        } else {
             fprintf(stderr, "Input public key hex is neither 66 nor 130 characters long. Cannot proceed.\n");
             return 1; // Input format invalid
        }
    }

    //printf("Input Public Key: %s\n", input_pubkey_hex_str);
    // Only print derived keys if they were successfully generated (length check >= 66/130)
    if (strlen(pub_hex_comp) >= 66) printf("Derived Compressed Public Key:   %s\n", pub_hex_comp);
    else printf("Derived Compressed Public Key:   Generation failed or input invalid\n");

    if (strlen(pub_hex_uncomp) >= 130) printf("Derived Uncompressed Public Key: %s\n", pub_hex_uncomp);
     else printf("Derived Uncompressed Public Key: Generation failed or input invalid\n");


    uint8_t temp_pub_bin[65]; // Max size for uncompressed
    uint8_t h160_bin[RIPEMD160_DIGEST_LENGTH];
    char h160_hex[RIPEMD160_DIGEST_LENGTH * 2 + 1];

    // HASH160 for compressed public key (if available)
    if (strlen(pub_hex_comp) == 66) { 
        if (hex2bin(pub_hex_comp, temp_pub_bin, 33) == 0) {
            hash160(temp_pub_bin, 33, h160_bin);
            bin2hex(h160_bin, RIPEMD160_DIGEST_LENGTH, h160_hex, sizeof(h160_hex));
            printf("HASH160 (Compressed PubKey):   %s\n", h160_hex);
        } else {
            printf("HASH160 (Compressed PubKey):   Error converting derived comp pubkey to bin\n");
        }
    } else {
         printf("HASH160 (Compressed PubKey):   Not available\n");
    }

    // HASH160 for uncompressed public key (if available)
    if (strlen(pub_hex_uncomp) == 130) { 
        if (hex2bin(pub_hex_uncomp, temp_pub_bin, 65) == 0) {
            hash160(temp_pub_bin, 65, h160_bin);
            bin2hex(h160_bin, RIPEMD160_DIGEST_LENGTH, h160_hex, sizeof(h160_hex));
            printf("HASH160 (Uncompressed PubKey): %s\n", h160_hex);
        } else {
             printf("HASH160 (Uncompressed PubKey): Error converting derived uncomp pubkey to bin\n");
        }
    } else {
        printf("HASH160 (Uncompressed PubKey): Not available\n");
    }


    char *addr_str; 

    printf("\n=== Addresses Generated from Compressed Public Key (%s) ===\n", (strlen(pub_hex_comp) == 66 && strcmp(pub_hex_comp, input_pubkey_hex_str) != 0) ? "Derived" : (strlen(pub_hex_comp) == 66 ? "Input" : "N/A"));
    if (strlen(pub_hex_comp) == 66) { 
        addr_str = public_key_to_address(pub_hex_comp, "P2PKH");
        if (addr_str) { printf("P2PKH:        %s\n", addr_str); free(addr_str); } else { printf("P2PKH:        Generation failed\n"); }

        addr_str = public_key_to_address(pub_hex_comp, "P2SH-P2WPKH");
        if (addr_str) { printf("P2SH-P2WPKH:  %s\n", addr_str); free(addr_str); } else { printf("P2SH-P2WPKH:  Generation failed\n"); }

        addr_str = public_key_to_address(pub_hex_comp, "BECH32");
        if (addr_str) { printf("BECH32:       %s\n", addr_str); free(addr_str); } else { printf("BECH32:       Generation failed\n"); }

        addr_str = public_key_to_address(pub_hex_comp, "P2WSH-P2WPKH");
        if (addr_str) { printf("P2WSH-P2WPKH: %s\n", addr_str); free(addr_str); } else { printf("P2WSH-P2WPKH: Generation failed\n"); }
    } else {
        printf("Compressed public key not available for address generation.\n");
    }


    printf("\n=== Addresses Generated from Uncompressed Public Key (%s) ===\n", (strlen(pub_hex_uncomp) == 130 && strcmp(pub_hex_uncomp, input_pubkey_hex_str) != 0) ? "Derived" : (strlen(pub_hex_uncomp) == 130 ? "Input" : "N/A"));
    if (strlen(pub_hex_uncomp) == 130) { 
        addr_str = public_key_to_address(pub_hex_uncomp, "P2PKH");
        if (addr_str) { printf("P2PKH:        %s\n", addr_str); free(addr_str); } else { printf("P2PKH:        Generation failed\n"); }

        addr_str = public_key_to_address(pub_hex_uncomp, "P2SH-P2WPKH");
        if (addr_str) { printf("P2SH-P2WPKH:  %s (Note: Non-standard)\n", addr_str); free(addr_str); } else { printf("P2SH-P2WPKH:  Generation failed (Note: Non-standard)\n"); }

        addr_str = public_key_to_address(pub_hex_uncomp, "BECH32");
        if (addr_str) { printf("BECH32:       %s (Note: Non-standard)\n", addr_str); free(addr_str); } else { printf("BECH32:       Generation failed (Note: Non-standard)\n"); }

        addr_str = public_key_to_address(pub_hex_uncomp, "P2WSH-P2WPKH");
        if (addr_str) { printf("P2WSH-P2WPKH: %s (Note: Non-standard)\n", addr_str); free(addr_str); } else { printf("P2WSH-P2WPKH: Generation failed (Note: Non-standard)\n"); }
    } else {
        printf("Uncompressed public key not available for address generation.\n");
    }

    printf("\n");
    return 0;
}
