/*author：https://github.com/8891689
 * Assist in creation ：ChatGPT 
 */
#include "ripemd160.h"
#include <string.h>

// 循环左移宏
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// RIPEMD-160五个基本非线性函数
#define F(x,y,z) ((x) ^ (y) ^ (z))
#define G(x,y,z) (((x) & (y)) | (~(x) & (z)))
#define H(x,y,z) (((x) | ~(y)) ^ (z))
#define I(x,y,z) (((x) & (z)) | ((y) & ~(z)))
#define J(x,y,z) ((x) ^ ((y) | ~(z)))

// 左线常量
#define KL0 0x00000000UL
#define KL1 0x5A827999UL
#define KL2 0x6ED9EBA1UL
#define KL3 0x8F1BBCDCUL
#define KL4 0xA953FD4EUL

// 右线常量
#define KR0 0x50A28BE6UL
#define KR1 0x5C4DD124UL
#define KR2 0x6D703EF3UL
#define KR3 0x7A6D76E9UL
#define KR4 0x00000000UL

// 左线消息索引顺序（共80步）
static const uint8_t r[80] = {
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
     3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
     1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
     4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13
};

// 右线消息索引顺序（共80步）
static const uint8_t rp[80] = {
     5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
     6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
    15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
     8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
    12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11
};

// 左线轮次旋转位数
static const uint8_t s[80] = {
    11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
     7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
    11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
    11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
     9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6
};

// 右线轮次旋转位数
static const uint8_t sp[80] = {
     8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
     9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
     9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
    15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
     8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11
};

static void ripemd160_transform(RIPEMD160_CTX *ctx, const uint8_t data[]) {
    uint32_t X[16];
    int i;
    // 将64字节数据转换为16个32位字（小端序）
    for (i = 0; i < 16; i++) {
        X[i] = ((uint32_t)data[4*i]) |
               ((uint32_t)data[4*i+1] << 8) |
               ((uint32_t)data[4*i+2] << 16) |
               ((uint32_t)data[4*i+3] << 24);
    }

    // 初始化左右两路的工作变量
    uint32_t A  = ctx->state[0];
    uint32_t B  = ctx->state[1];
    uint32_t C  = ctx->state[2];
    uint32_t D  = ctx->state[3];
    uint32_t E  = ctx->state[4];

    uint32_t A1 = A;
    uint32_t B1 = B;
    uint32_t C1 = C;
    uint32_t D1 = D;
    uint32_t E1 = E;

    uint32_t T, f, K, Kp;

    // 80步迭代（左线与右线并行进行）
    for (i = 0; i < 80; i++) {
        // 左线：根据步数选择不同的非线性函数和常量
        if (i < 16) {
            f = F(B, C, D);
            K = KL0;
        } else if (i < 32) {
            f = G(B, C, D);
            K = KL1;
        } else if (i < 48) {
            f = H(B, C, D);
            K = KL2;
        } else if (i < 64) {
            f = I(B, C, D);
            K = KL3;
        } else {
            f = J(B, C, D);
            K = KL4;
        }
        T = ROL(A + f + X[r[i]] + K, s[i]) + E;
        A = E;
        E = D;
        D = ROL(C, 10);
        C = B;
        B = T;

        // 右线：步数不同，非线性函数顺序为 J, I, H, G, F
        if (i < 16) {
            f = J(B1, C1, D1);
            Kp = KR0;
        } else if (i < 32) {
            f = I(B1, C1, D1);
            Kp = KR1;
        } else if (i < 48) {
            f = H(B1, C1, D1);
            Kp = KR2;
        } else if (i < 64) {
            f = G(B1, C1, D1);
            Kp = KR3;
        } else {
            f = F(B1, C1, D1);
            Kp = KR4;
        }
        T = ROL(A1 + f + X[rp[i]] + Kp, sp[i]) + E1;
        A1 = E1;
        E1 = D1;
        D1 = ROL(C1, 10);
        C1 = B1;
        B1 = T;
    }

    // 将左右两路的结果组合更新状态
    uint32_t temp = ctx->state[1] + C + D1;
    ctx->state[1] = ctx->state[2] + D + E1;
    ctx->state[2] = ctx->state[3] + E + A1;
    ctx->state[3] = ctx->state[4] + A + B1;
    ctx->state[4] = ctx->state[0] + B + C1;
    ctx->state[0] = temp;
}

void ripemd160_init(RIPEMD160_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    // 初始化状态（RIPEMD-160标准初始值）
    ctx->state[0] = 0x67452301UL;
    ctx->state[1] = 0xEFCDAB89UL;
    ctx->state[2] = 0x98BADCFEUL;
    ctx->state[3] = 0x10325476UL;
    ctx->state[4] = 0xC3D2E1F0UL;
}

void ripemd160_update(RIPEMD160_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            ripemd160_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void ripemd160_final(RIPEMD160_CTX *ctx, uint8_t hash[RIPEMD160_DIGEST_LENGTH]) {
    size_t i = ctx->datalen;

    // 添加0x80后填充0，直到数据长度达到56字节
    ctx->data[i++] = 0x80;
    if (i > 56) {
        while (i < 64)
            ctx->data[i++] = 0x00;
        ripemd160_transform(ctx, ctx->data);
        i = 0;
    }
    while (i < 56)
        ctx->data[i++] = 0x00;

    // 追加消息长度（单位：比特），以小端序写入
    ctx->bitlen += ctx->datalen * 8;
    for (i = 0; i < 8; i++) {
        ctx->data[56 + i] = (uint8_t)((ctx->bitlen >> (8 * i)) & 0xff);
    }
    ripemd160_transform(ctx, ctx->data);

    // 输出哈希（状态以小端序输出，共20字节）
    for (i = 0; i < 5; i++) {
        hash[4*i]     = ctx->state[i] & 0xff;
        hash[4*i + 1] = (ctx->state[i] >> 8) & 0xff;
        hash[4*i + 2] = (ctx->state[i] >> 16) & 0xff;
        hash[4*i + 3] = (ctx->state[i] >> 24) & 0xff;
    }
}

void ripemd160(const uint8_t *data, size_t len, uint8_t hash[RIPEMD160_DIGEST_LENGTH]) {
    RIPEMD160_CTX ctx;
    ripemd160_init(&ctx);
    ripemd160_update(&ctx, data, len);
    ripemd160_final(&ctx, hash);
}

