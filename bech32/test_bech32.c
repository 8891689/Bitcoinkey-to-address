// gcc -o test_bech32 test_bech32.c bech32.c
// ./test_bech32

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "bech32.h"

void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int test_encode_decode(const char *hrp, int witver, const uint8_t *witprog, size_t proglen) {
    char encoded[200];
    int decoded_ver;
    uint8_t decoded_prog[200];
    size_t decoded_prog_len = sizeof(decoded_prog);

    printf("Testing HRP: %s, Version: %d, Program Length: %zu\n", hrp, witver, proglen);
    printf("  Original program: ");
    print_hex(witprog, proglen);

    // Encode
    if (!segwit_addr_encode(encoded, hrp, witver, witprog, proglen)) {
        printf("  Encoding failed.\n");
        return 1;
    }
    printf("  Encoded address: %s\n", encoded);

    // Decode
    if (!segwit_addr_decode(encoded, hrp, &decoded_ver, decoded_prog, &decoded_prog_len)) {
        printf("  Decoding failed.\n");
        return 1;
    }
    printf("  Decoded version: %d\n", decoded_ver);
    printf("  Decoded program: ");
    print_hex(decoded_prog, decoded_prog_len);

    // Verify
    if (witver != decoded_ver) {
        printf("  Version mismatch.\n");
        return 1;
    }
    if (proglen != decoded_prog_len) {
        printf("  Program length mismatch.\n");
        return 1;
    }
    if (memcmp(witprog, decoded_prog, proglen) != 0) {
        printf("  Program data mismatch.\n");
        return 1;
    }
    printf("  Test passed.\n\n");
    return 0;
}

int test_invalid_decode(const char *hrp, const char *address)
{
    int decoded_ver;
    uint8_t decoded_prog[200];
    size_t decoded_prog_len = sizeof(decoded_prog);
    printf("Testing invalid decode HRP: %s,  Address: %s\n", hrp, address);
    if(segwit_addr_decode(address, hrp, &decoded_ver, decoded_prog, &decoded_prog_len)) {
        printf("  Error: Invalid address should have failed to decode, but it did not.\n");
        return 1;
    } else {
       printf("  Test Passed, invalid address failed to decode as expected.\n");
    }
    return 0;

}


int test_uppercase_hrp_fail(const char *hrp, int witver, const uint8_t *witprog, size_t proglen) {
     char encoded[200];
     printf("Testing uppercase HRP fail: %s, Version: %d, Program Length: %zu\n", hrp, witver, proglen);

    if (segwit_addr_encode(encoded, hrp, witver, witprog, proglen)) {
        printf("  Error: Uppercase HRP should have failed to encode, but it did not.\n");
       return 1;
    } else {
       printf("  Test Passed, uppercase HRP failed to encode as expected.\n");
    }
    return 0;
}



int main(void) {
    uint8_t prog20[] = {0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x1c, 0x0e, 0xf6, 0x4b, 0x8e};
    uint8_t prog32[] = {
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x1c,
        0x0e, 0xf6, 0x4b, 0x8e, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45
    };
    uint8_t prog40[] = {
        0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x1c,
        0x0e, 0xf6, 0x4b, 0x8e, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    };

    // Test valid cases
    if(test_encode_decode("bc", 0, prog20, sizeof(prog20)) != 0) return 1;
    if(test_encode_decode("tb", 0, prog20, sizeof(prog20)) != 0) return 1;
    if(test_encode_decode("bc", 1, prog20, sizeof(prog20)) != 0) return 1;
    if(test_uppercase_hrp_fail("BC", 0, prog20, sizeof(prog20)) != 0) return 1; // test uppercase HRP fail
    if(test_encode_decode("test", 0, prog32, sizeof(prog32)) != 0) return 1;
    if(test_encode_decode("test", 0, prog40, sizeof(prog40)) != 0) return 1;
    if(test_encode_decode("z", 0, prog20, sizeof(prog20)) != 0) return 1; // test short HRP

    uint8_t short_prog[] = {0x01, 0x02, 0x03};
    if(test_encode_decode("test", 0, short_prog, sizeof(short_prog)) != 0) return 1;
    uint8_t long_prog[64];
    for (size_t i = 0; i < 64; i++) {
        long_prog[i] = i;
    }
    if(test_encode_decode("test", 0, long_prog, sizeof(long_prog)) != 0) return 1;

    // Test invalid decode cases
     if(test_invalid_decode("bc","bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5") != 0) return 1;
    if(test_invalid_decode("bc", "BC1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5") != 0) return 1;
    if(test_invalid_decode("bc", "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs5") != 0) return 1;
    if(test_invalid_decode("bc", "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs5") != 0) return 1;
     if(test_invalid_decode("bc","bc10qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5a") != 0) return 1;
    if(test_invalid_decode("bc","bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5w") != 0) return 1;
    if(test_invalid_decode("bc","bc1zqw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5") != 0) return 1;
    if(test_invalid_decode("bc","tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5") != 0) return 1;

    printf("All tests passed.\n");
    return 0;
}
