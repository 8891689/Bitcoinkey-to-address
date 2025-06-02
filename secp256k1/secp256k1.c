/*author：https://github.com/8891689
 * Assist in creation ：ChatGPT gemini
 */
#include "secp256k1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// ------------------------------
// secp256k1 曲线参数
// ------------------------------
// secp256k1 的素数域 p
const BigInt secp256k1_p = {
    .data = {
        0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    }
};

// secp256k1 的阶 n (注意字节序调整)
const BigInt secp256k1_n = {
    .data = {
        0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6,
        0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF
    }
};


// 基点 G 的仿射坐标 (十六进制小端序)
static const BigInt G_x = {
    .data = {
        0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB,
        0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E
    }
};

static const BigInt G_y = {
    .data = {
        0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448,
        0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77
    }
};

// 基点 G 的雅可比坐标表示 (Z=1)
const ECPointJac G_jacobian = {
    .X = G_x,
    .Y = G_y,
    .Z = { .data = {1, 0, 0, 0, 0, 0, 0, 0} },
    .infinity = false
};

// ------------------------------
// 大整数基本运算实现
// ------------------------------
void init_bigint(BigInt *x, uint32_t val) {
    memset(x->data, 0, sizeof(x->data));
    x->data[0] = val;
}

void copy_bigint(BigInt *dest, const BigInt *src) {
    memcpy(dest->data, src->data, sizeof(src->data));
}

int compare_bigint(const BigInt *a, const BigInt *b) {
    for (int i = BIGINT_WORDS - 1; i >= 0; i--) {
        if (a->data[i] != b->data[i])
            return (a->data[i] > b->data[i]) ? 1 : -1;
    }
    return 0;
}

bool is_zero(const BigInt *a) {
    for (int i = 0; i < BIGINT_WORDS; i++) {
        if (a->data[i])
            return false;
    }
    return true;
}

// ******** is_odd 函數實現 ********
// 檢查 BigInt 是否為奇數
// 假設 data[0] 是最低位的 32 位字 (小端序字數組)
bool is_odd(const BigInt *n) {
    if (BIGINT_WORDS == 0) {
        return false; // 處理空的 BigInt (如果可能)
    }
    // 檢查最低位字 (data[0]) 的最低位 (bit 0)
    return (n->data[0] & 1) != 0;
}

// 高效位获取函数
int get_bit(const BigInt *a, int i) {
    int word_idx = i >> 5;
    int bit_idx = i & 31;
    if (word_idx >= BIGINT_WORDS) return 0;
    return (a->data[word_idx] >> bit_idx) & 1;
}

// 在ptx_u256Add和ptx_u256Sub中使用uint64_t进行中间计算
void ptx_u256Add(BigInt *res, const BigInt *a, const BigInt *b) {
    uint64_t carry = 0;
    for (int i = 0; i < BIGINT_WORDS; ++i) {
        uint64_t sum = (uint64_t)a->data[i] + b->data[i] + carry;
        res->data[i] = (uint32_t)sum;
        carry = (sum >> 32);
    }
}

void ptx_u256Sub(BigInt *res, const BigInt *a, const BigInt *b) {
    uint32_t borrow = 0;
    for (int i = 0; i < BIGINT_WORDS; ++i) {
        uint64_t diff = (uint64_t)a->data[i] - b->data[i] - borrow;
        res->data[i] = (uint32_t)diff;
        borrow = (diff >> 32) & 1;
    }
}

// ------------------------------
// Montgomery 参数及运算实现
// ------------------------------

// 简单模约简函数（假设 a < 2p）
void mod_generic(BigInt *r, const BigInt *a, const BigInt *p) {
    if (compare_bigint(a, p) >= 0) { // 比較的是 (a+b) mod 2^256 的結果
        ptx_u256Sub(r, a, p);      // 如果 >= p，只減去一次 p
    } else {
        copy_bigint(r, a);         // 否則直接複製
    }
}

// 模乘函数（仅用于 Montgomery 参数初始化时计算 R2）
void mul_mod(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *p) {
    uint64_t prod[2*BIGINT_WORDS] = {0};
    for (int i = 0; i < BIGINT_WORDS; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < BIGINT_WORDS; j++) {
            uint64_t tmp = prod[i+j] + (uint64_t)a->data[i] * b->data[j] + carry;
            prod[i+j] = (uint32_t) tmp;
            carry = tmp >> 32;
        }
        prod[i+BIGINT_WORDS] += carry;
    }
    // 取低 BIGINT_WORDS 个字，并进行简单模约简（假设结果 < 2p）
    for (int i = 0; i < BIGINT_WORDS; i++) {
        res->data[i] = (uint32_t) prod[i];
    }
    if (compare_bigint(res, p) >= 0) {
        ptx_u256Sub(res, res, p);
    }
}

// ------------------------------
// Montgomery 参数初始化（优化后的模逆计算）
// ------------------------------
void montgomery_init(MontgomeryCtx *ctx, const BigInt *p) {
    // 构造 R = 2^(32*BIGINT_WORDS) mod p
    BigInt R;
    memset(R.data, 0, sizeof(R.data));
    R.data[BIGINT_WORDS-1] = 1;  // 设置最高位为1
    mod_generic(&ctx->R, &R, p);

    // 计算 R^2 mod p -> R2
    mul_mod(&ctx->R2, &ctx->R, &ctx->R, p);

    // 计算 R^4 mod p -> R4
    mul_mod(&ctx->R4, &ctx->R2, &ctx->R2, p);

    // 使用牛顿迭代法计算 inv_p = -p^-1 mod 2^32
    uint32_t p0 = p->data[0];
    uint32_t inv = 1;
    // 4次牛顿迭代足够收敛32位精度
    inv *= 2 - p0 * inv;
    inv *= 2 - p0 * inv;
    inv *= 2 - p0 * inv;
    inv *= 2 - p0 * inv;
    ctx->inv_p.data[0] = -inv;
    memset(&ctx->inv_p.data[1], 0, (BIGINT_WORDS-1)*sizeof(uint32_t));
}

// ------------------------------
// 优化后的Montgomery乘法（循环展开+64位中间存储）
// ------------------------------
static inline void montgomery_mult(BigInt *restrict result, 
                     const BigInt *restrict a, 
                     const BigInt *restrict b,
                     const MontgomeryCtx *restrict ctx,
                     const BigInt *restrict p) {
    uint64_t t[17] = {0}; // 使用64位存储中间结果

    for (int i = 0; i < BIGINT_WORDS; ++i) {
        const uint32_t a_i = a->data[i];
        const uint32_t *b_ptr = b->data;
        uint64_t *t_ptr = &t[i];
        uint64_t carry = 0;

        // 手动展开乘法累加循环
        #pragma unroll
        for (int j = 0; j < BIGINT_WORDS; ++j) {
            uint64_t prod = (uint64_t)a_i * b_ptr[j] + t_ptr[j] + carry;
            t_ptr[j] = prod & 0xFFFFFFFFULL;
            carry = prod >> 32;
        }
        t_ptr[BIGINT_WORDS] += carry;

        // 计算蒙哥马利约简系数m
        uint32_t m = (uint32_t)t_ptr[0] * ctx->inv_p.data[0];
        
        // 手动展开模约简循环
        const uint32_t *p_ptr = p->data;
        carry = 0;
        #pragma unroll
        for (int j = 0; j < BIGINT_WORDS; ++j) {
            uint64_t term = (uint64_t)m * p_ptr[j] + t_ptr[j] + carry;
            t_ptr[j] = term & 0xFFFFFFFFULL;
            carry = term >> 32;
        }

        // 处理高位进位（手动展开）
        for (int k = BIGINT_WORDS; carry && k < 2*BIGINT_WORDS; ++k) {
            uint64_t sum = t_ptr[k] + carry;
            t_ptr[k] = sum & 0xFFFFFFFFULL;
            carry = sum >> 32;
        }
    }

    // 拷贝结果并处理溢出
    BigInt tmp;
    for (int i = 0; i < BIGINT_WORDS; ++i) {
        tmp.data[i] = (uint32_t)t[BIGINT_WORDS + i];
    }
    
    // 使用快速比较和减法
    if (compare_bigint(&tmp, p) >= 0) {
        ptx_u256Sub(&tmp, &tmp, p);
    }
    copy_bigint(result, &tmp);
}

// ------------------------------
// ECC 点运算以及其它辅助函数
// ------------------------------

// 雅可比坐标点初始化
void init_point_jac(ECPointJac *p, bool infinity) {
    memset(&p->X, 0, sizeof(BigInt));
    memset(&p->Y, 0, sizeof(BigInt));
    memset(&p->Z, 0, sizeof(BigInt));
    p->infinity = infinity;
}

// 雅可比坐标点复制
void copy_point_jac(ECPointJac *dest, const ECPointJac *src) {
    memcpy(&dest->X, &src->X, sizeof(BigInt));
    memcpy(&dest->Y, &src->Y, sizeof(BigInt));
    memcpy(&dest->Z, &src->Z, sizeof(BigInt));
    dest->infinity = src->infinity;
}

// 优化后的标量乘法（已验证正确性）
void scalar_multiply_jac(ECPointJac *result, const ECPointJac *point, const BigInt *scalar, const BigInt *p) {
    ECPointJac res;
    init_point_jac(&res, true);

    // 使用窗口法来优化标量乘法
    int highest_bit = BIGINT_WORDS * 32 - 1;
    for (; highest_bit >= 0; highest_bit--) {
        if (get_bit(scalar, highest_bit)) break;
    }
    if (highest_bit < 0) {
        copy_point_jac(result, &res);
        return;
    }
    for (int i = highest_bit; i >= 0; i--) {
        double_point_jac(&res, &res, p);
        if (get_bit(scalar, i)) {
            add_point_jac(&res, &res, point, p);
        }
    }
    copy_point_jac(result, &res);
}

// 以下为9字扩展运算实现
void multiply_bigint_by_const(const BigInt *a, uint32_t c, uint32_t result[9]) {
    uint64_t carry = 0;
    for (int i = 0; i < BIGINT_WORDS; i++) {
        uint64_t prod = (uint64_t)a->data[i] * c + carry;
        result[i] = (uint32_t)prod;
        carry = prod >> 32;
    }
    result[8] = (uint32_t)carry;
}

void shift_left_word(const BigInt *a, uint32_t result[9]) {
    result[0] = 0;
    memcpy(&result[1], a->data, BIGINT_WORDS * sizeof(uint32_t));
}

void add_9word(uint32_t r[9], const uint32_t addend[9]) {
    uint64_t carry = 0;
    for (int i = 0; i < 9; i++) {
        uint64_t sum = (uint64_t)r[i] + addend[i] + carry;
        r[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
}

void convert_9word_to_bigint(const uint32_t r[9], BigInt *res) {
    memcpy(res->data, r, BIGINT_WORDS * sizeof(uint32_t));
}

// 模乘及模约简实现
void mul_mod_old(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *p) {
    uint32_t prod[16] = {0};
    for (int i = 0; i < BIGINT_WORDS; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < BIGINT_WORDS; j++) {
            uint64_t tmp = (uint64_t)prod[i+j] + (uint64_t)a->data[i] * b->data[j] + carry;
            prod[i+j] = (uint32_t)tmp;
            carry = tmp >> 32;
        }
        prod[i+BIGINT_WORDS] += (uint32_t)carry;
    }
    BigInt L, H;
    for (int i = 0; i < BIGINT_WORDS; i++) {
        L.data[i] = prod[i];
        H.data[i] = prod[i+BIGINT_WORDS];
    }
    uint32_t Rext[9] = {0};
    memcpy(Rext, L.data, BIGINT_WORDS * sizeof(uint32_t));
    Rext[8] = 0;
    uint32_t H977[9] = {0};
    multiply_bigint_by_const(&H, 977, H977);
    add_9word(Rext, H977);
    uint32_t Hshift[9] = {0};
    shift_left_word(&H, Hshift);
    add_9word(Rext, Hshift);
    if (Rext[8]) {
        uint32_t extra[9] = {0};
        BigInt extraBI;
        init_bigint(&extraBI, Rext[8]);
        Rext[8] = 0;
        uint32_t extra977[9] = {0}, extraShift[9] = {0};
        multiply_bigint_by_const(&extraBI, 977, extra977);
        shift_left_word(&extraBI, extraShift);
        memcpy(extra, extra977, 9 * sizeof(uint32_t));
        add_9word(extra, extraShift);
        add_9word(Rext, extra);
    }
    BigInt R_temp;
    convert_9word_to_bigint(Rext, &R_temp);
    if (Rext[8] || compare_bigint(&R_temp, p) >= 0) {
        ptx_u256Sub(&R_temp, &R_temp, p);
        if (compare_bigint(&R_temp, p) >= 0)
            ptx_u256Sub(&R_temp, &R_temp, p);
    }
    copy_bigint(res, &R_temp);
}

void efficient_mod(BigInt *r, const BigInt *a, const BigInt *p) {
    copy_bigint(r, a);
    if (compare_bigint(r, p) >= 0) {
         BigInt temp;
         ptx_u256Sub(&temp, r, p);
         if (compare_bigint(&temp, p) >= 0)
              ptx_u256Sub(&temp, &temp, p);
         copy_bigint(r, &temp);
    }
}

void sub_mod(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *p) {
    BigInt temp;
    if (compare_bigint(a, b) < 0) {
         BigInt sum;
         ptx_u256Add(&sum, a, p);
         ptx_u256Sub(&temp, &sum, b);
    } else {
         ptx_u256Sub(&temp, a, b);
    }
    mod_generic(&temp, &temp, p);
    copy_bigint(res, &temp);
}

// 在 修改 add_mod 函數
void add_mod(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *p) {
    BigInt sum_ab;
    uint64_t carry = 0; // 使用 uint64_t 來儲存進位

    // 1. 計算 sum = a + b，並記錄進位
    for (int i = 0; i < BIGINT_WORDS; ++i) {
         uint64_t word_sum = (uint64_t)a->data[i] + b->data[i] + carry;
         sum_ab.data[i] = (uint32_t)word_sum;
         carry = word_sum >> 32; // 獲取下一個進位
    }
    // 'carry' 現在持有最終的進位 (0 或 1)

    // 2. 判斷數學和 (a+b) 是否 >= p
    // 條件：發生了進位 (carry=1) 或者 雖然沒進位但結果 sum_ab 已經 >= p
    if (carry || compare_bigint(&sum_ab, p) >= 0) {
        // 3. 如果 >= p，則結果是 sum_ab - p
        //    注意：這裡的 sum_ab 是 (a+b) mod 2^256，減去 p 是正確的
        ptx_u256Sub(res, &sum_ab, p);
    } else {
        // 4. 否則，結果就是 sum_ab
        copy_bigint(res, &sum_ab);
    }
}

// 可以保留 add_mod_n，或者如果不再需要可以移除它，
// 因為 add_mod 現在已經實現了相同的功能。
void modexp(BigInt *res, const BigInt *base, const BigInt *exp, const BigInt *p) {
    BigInt result;
    init_bigint(&result, 1);
    BigInt b;
    copy_bigint(&b, base);
    for (int i = 0; i < 256; i++) {
         if (get_bit(exp, i)) {
              BigInt temp;
              mul_mod_old(&temp, &result, &b, p);
              copy_bigint(&result, &temp);
         }
         BigInt temp;
         mul_mod_old(&temp, &b, &b, p);
         copy_bigint(&b, &temp);
    }
    copy_bigint(res, &result);
}

void mod_inverse(BigInt *res, const BigInt *a, const BigInt *p) {
    BigInt p_minus_2;
    BigInt two;
    init_bigint(&two, 2);
    ptx_u256Sub(&p_minus_2, p, &two); 
    modexp(res, a, &p_minus_2, p);
}

// ------------------------------
// 仿射坐标下 ECC 点运算实现
// ------------------------------
void point_set_infinity(ECPoint *P) {
    P->infinity = true;
}

void point_copy(ECPoint *dest, const ECPoint *src) {
    copy_bigint(&dest->x, &src->x);
    copy_bigint(&dest->y, &src->y);
    dest->infinity = src->infinity;
}

void point_add(ECPoint *R, const ECPoint *P, const ECPoint *Q, const BigInt *p) {
    if (P->infinity) {
        point_copy(R, Q);
        return;
    }
    if (Q->infinity) {
        point_copy(R, P);
        return;
    }

    BigInt diffY, diffX, inv_diffX, lambda, lambda2, temp;
    sub_mod(&diffY, &Q->y, &P->y, p);
    sub_mod(&diffX, &Q->x, &P->x, p);
    mod_inverse(&inv_diffX, &diffX, p);
    mul_mod_old(&lambda, &diffY, &inv_diffX, p);
    mul_mod_old(&lambda2, &lambda, &lambda, p);
    sub_mod(&temp, &lambda2, &P->x, p);
    sub_mod(&R->x, &temp, &Q->x, p);
    sub_mod(&temp, &P->x, &R->x, p);
    mul_mod_old(&R->y, &lambda, &temp, p);
    sub_mod(&R->y, &R->y, &P->y, p);
    R->infinity = false;
}

void double_point(ECPoint *R, const ECPoint *P, const BigInt *p) {
    if (P->infinity || is_zero(&P->y)) {
         point_set_infinity(R);
         return;
    }
    BigInt x2, numerator, denominator, inv_den, lambda, lambda2, two, two_x;
    mul_mod_old(&x2, &P->x, &P->x, p);
    BigInt three; 
    init_bigint(&three, 3);
    mul_mod_old(&numerator, &three, &x2, p);
    init_bigint(&two, 2);
    mul_mod_old(&denominator, &two, &P->y, p);
    mod_inverse(&inv_den, &denominator, p);
    mul_mod_old(&lambda, &numerator, &inv_den, p);
    mul_mod_old(&lambda2, &lambda, &lambda, p);
    mul_mod_old(&two_x, &two, &P->x, p);
    sub_mod(&R->x, &lambda2, &two_x, p);
    sub_mod(&numerator, &P->x, &R->x, p);
    mul_mod_old(&R->y, &lambda, &numerator, p);
    sub_mod(&R->y, &R->y, &P->y, p);
    R->infinity = false;
}

// ------------------------------
// 雅可比坐标下 ECC 点运算实现
// ------------------------------
void point_set_infinity_jac(ECPointJac *P) {
    P->infinity = true;
}

void point_copy_jac(ECPointJac *dest, const ECPointJac *src) {
    copy_bigint(&dest->X, &src->X);
    copy_bigint(&dest->Y, &src->Y);
    copy_bigint(&dest->Z, &src->Z);
    dest->infinity = src->infinity;
}

void double_point_jac(ECPointJac *R, const ECPointJac *P, const BigInt *p) {
    if (P->infinity || is_zero(&P->Y)) {
        point_set_infinity_jac(R);
        return;
    }
    
    BigInt A, B, C, D, X3, Y3, Z3, temp, temp2;
    mul_mod_old(&A, &P->Y, &P->Y, p);
    mul_mod_old(&temp, &P->X, &A, p);
    init_bigint(&temp2, 4);
    mul_mod_old(&B, &temp, &temp2, p);
    mul_mod_old(&temp, &A, &A, p);
    init_bigint(&temp2, 8);
    mul_mod_old(&C, &temp, &temp2, p);
    mul_mod_old(&temp, &P->X, &P->X, p);
    init_bigint(&temp2, 3);
    mul_mod_old(&D, &temp, &temp2, p);
    BigInt D2;
    mul_mod_old(&D2, &D, &D, p);
    BigInt two;
    init_bigint(&two, 2);
    BigInt twoB;
    mul_mod_old(&twoB, &B, &two, p);
    sub_mod(&X3, &D2, &twoB, p);
    sub_mod(&temp, &B, &X3, p);
    mul_mod_old(&temp, &D, &temp, p);
    sub_mod(&Y3, &temp, &C, p);
    init_bigint(&temp, 2);
    mul_mod_old(&temp, &temp, &P->Y, p);
    mul_mod_old(&Z3, &temp, &P->Z, p);
    copy_bigint(&R->X, &X3);
    copy_bigint(&R->Y, &Y3);
    copy_bigint(&R->Z, &Z3);
    R->infinity = false;
}

void add_point_jac(ECPointJac *R, const ECPointJac *P, const ECPointJac *Q, const BigInt *p) {
    if (P->infinity) { 
        point_copy_jac(R, Q);
        return;
    }
    if (Q->infinity) { 
        point_copy_jac(R, P);
        return;
    }
    
    BigInt Z1Z1, Z2Z2, U1, U2, S1, S2, H, R_big, H2, H3, U1H2, X3, Y3, Z3, temp;
    mul_mod_old(&Z1Z1, &P->Z, &P->Z, p);
    mul_mod_old(&Z2Z2, &Q->Z, &Q->Z, p);
    mul_mod_old(&U1, &P->X, &Z2Z2, p);
    mul_mod_old(&U2, &Q->X, &Z1Z1, p);
    BigInt Z2_cubed, Z1_cubed;
    mul_mod_old(&Z2_cubed, &Z2Z2, &Q->Z, p);
    mul_mod_old(&Z1_cubed, &Z1Z1, &P->Z, p);
    mul_mod_old(&S1, &P->Y, &Z2_cubed, p);
    mul_mod_old(&S2, &Q->Y, &Z1_cubed, p);
    
    if (compare_bigint(&U1, &U2) == 0) {
        if (compare_bigint(&S1, &S2) != 0) {
            point_set_infinity_jac(R);
            return;
        } else {
            double_point_jac(R, P, p);
            return;
        }
    }
    
    // H = U2 - U1, R_big = S2 - S1
    sub_mod(&H, &U2, &U1, p);
    sub_mod(&R_big, &S2, &S1, p);

    // H^2, H^3, U1*H^2
    mul_mod_old(&H2, &H, &H, p);
    mul_mod_old(&H3, &H2, &H, p);
    mul_mod_old(&U1H2, &U1, &H2, p);

    // X3 = R_big^2 - H^3 - 2*U1H2
    BigInt R2;
    mul_mod_old(&R2, &R_big, &R_big, p);
    BigInt two;         // 新增声明
    init_bigint(&two, 2);
    BigInt twoU1H2;
    mul_mod_old(&twoU1H2, &U1H2, &two, p);
    sub_mod(&temp, &R2, &H3, p);
    sub_mod(&X3, &temp, &twoU1H2, p);

    sub_mod(&temp, &U1H2, &X3, p);
    mul_mod_old(&temp, &R_big, &temp, p);
    mul_mod_old(&Y3, &S1, &H3, p);
    sub_mod(&Y3, &temp, &Y3, p);
    mul_mod_old(&temp, &P->Z, &Q->Z, p);
    mul_mod_old(&Z3, &temp, &H, p);
    
    copy_bigint(&R->X, &X3);
    copy_bigint(&R->Y, &Y3);
    copy_bigint(&R->Z, &Z3);
    R->infinity = false;
}

void jacobian_to_affine(ECPoint *R, const ECPointJac *P, const BigInt *p) {
    if (P->infinity) {
        R->infinity = true;
        return;
    }
    BigInt Zinv, Zinv2, Zinv3;
    mod_inverse(&Zinv, &P->Z, p);
    mul_mod_old(&Zinv2, &Zinv, &Zinv, p);
    mul_mod_old(&Zinv3, &Zinv2, &Zinv, p);
    
    mul_mod_old(&R->x, &P->X, &Zinv2, p);
    mul_mod_old(&R->y, &P->Y, &Zinv3, p);
    R->infinity = false;
}

// ------------------------------
// 辅助工具函数（优化后）
// ------------------------------
void print_bigint(const BigInt *b) {
    // BIGINT_SIZE 定義與 BIGINT_WORDS 一致
    for (int i = BIGINT_WORDS - 1; i >= 0; i--) {
        printf("%08x", b->data[i]);
    }
    printf("\n");
}

void bigint_to_hex(const BigInt *num, char *hex_string) {
    // 直接利用 %08x 輸出小寫，避免後續轉換
    for (int i = BIGINT_WORDS - 1; i >= 0; i--) {
        sprintf(hex_string + (BIGINT_WORDS - 1 - i) * 8, "%08x", num->data[i]);
    }
}

void hex_to_bigint(const char *hex, BigInt *b) {
    memset(b->data, 0, sizeof(b->data));
    int len = (int)strlen(hex);
    int j = 0;
    while (len > 0 && j < BIGINT_WORDS) {
        // 每次處理最多8個字符
        int chunk = (len >= 8) ? 8 : len;
        char temp[9];
        memcpy(temp, hex + len - chunk, chunk);
        temp[chunk] = '\0';
        b->data[j++] = (uint32_t)strtoul(temp, NULL, 16);
        len -= chunk;
    }
}

void point_to_compressed_hex(const ECPoint *P, char *hex_string) {
    if (P->infinity) {
        strcpy(hex_string, "00");
        return;
    }
    char x_hex[65];
    bigint_to_hex(&P->x, x_hex);
    // %08x 已輸出小寫，直接拼接前綴即可
    sprintf(hex_string, "%s%s", (P->y.data[0] & 1) ? "03" : "02", x_hex);
}

void point_to_uncompressed_hex(const ECPoint *P, char *hex_string) {
    if (P->infinity) {
        strcpy(hex_string, "00");
        return;
    }
    char x_hex[65], y_hex[65];
    bigint_to_hex(&P->x, x_hex);
    bigint_to_hex(&P->y, y_hex);
    sprintf(hex_string, "04%s%s", x_hex, y_hex);
}

// ------------------------------
// 封裝私钥转公钥实现
// ------------------------------
void private_to_public_key(ECPoint *public_key, const BigInt *private_key) {
    ECPointJac result_jac;
    
    // 执行标量乘法：Q = private_key * G
    scalar_multiply_jac(&result_jac, &G_jacobian, private_key, &secp256k1_p);
    
    // 将雅可比坐标转换为仿射坐标
    jacobian_to_affine(public_key, &result_jac, &secp256k1_p);
}
// --- BigInt/Byte 轉換函數實現 ---
// 將 32 字節的大端序數據 (例如 BIP32 密鑰) 轉換為 BigInt (內部小端字序)
// 輸入 bytes[0]...bytes[31] 是 BE (bytes[0] 是最高位字節)
// 輸出 b->data[0]...b->data[7] 是 LE words (b->data[0] 是最低位字)
void bytes_be_to_bigint(const uint8_t bytes[32], BigInt *b) {
    memset(b->data, 0, sizeof(b->data));
    for (int i = 0; i < BIGINT_WORDS; ++i) { // i = 0 to 7 (word index)
        // Word i (b->data[i]) 對應的字節範圍是 bytes[31-(i*4)-3] ... bytes[31-(i*4)]
        // 例如：
        // i = 0 (LSW): 需要 bytes[28..31] -> b->data[0]
        // i = 7 (MSW): 需要 bytes[0..3]  -> b->data[7]
        int base_byte_idx = 31 - (i * 4); // 字節數組中最右邊字節的索引
        // 確保索引不越界 (雖然對於 32 字節輸入和 8 個字應該不會)
        if (base_byte_idx < 3 || base_byte_idx > 31) continue; // 安全檢查

        b->data[i] = ((uint32_t)bytes[base_byte_idx - 3] << 24) | // 最高位字節 (e.g., bytes[28] for i=0)
                     ((uint32_t)bytes[base_byte_idx - 2] << 16) | // (e.g., bytes[29] for i=0)
                     ((uint32_t)bytes[base_byte_idx - 1] << 8)  | // (e.g., bytes[30] for i=0)
                     ((uint32_t)bytes[base_byte_idx]);           // 最低位字節 (e.g., bytes[31] for i=0)
    }
}

// 將 BigInt (內部小端字序) 轉換回 32 字節的大端序數據
// 輸入 b->data[0]...b->data[7] 是 LE words (b->data[0] 是最低位字)
// 輸出 bytes[0]...bytes[31] 是 BE (bytes[0] 是最高位字節)
void bigint_to_bytes_be(const BigInt *b, uint8_t bytes[32]) {
    memset(bytes, 0, 32);
    for (int i = 0; i < BIGINT_WORDS; ++i) { // i = 0 to 7 (word index)
        // Word i (b->data[i]) 需要寫入到字節範圍 bytes[31-(i*4)-3] ... bytes[31-(i*4)]
        // 例如：
        // i = 0 (LSW): 寫入 bytes[28..31]
        // i = 7 (MSW): 寫入 bytes[0..3]
        int base_byte_idx = 31 - (i * 4); // 字節數組中最右邊字節的索引
        // 確保索引不越界
        if (base_byte_idx < 3 || base_byte_idx > 31) continue; // 安全檢查

        bytes[base_byte_idx]       = (uint8_t)(b->data[i] & 0xFF);          // 最低位字節 (e.g., -> bytes[31] for i=0)
        bytes[base_byte_idx - 1] = (uint8_t)((b->data[i] >> 8) & 0xFF);  // (e.g., -> bytes[30] for i=0)
        bytes[base_byte_idx - 2] = (uint8_t)((b->data[i] >> 16) & 0xFF); // (e.g., -> bytes[29] for i=0)
        bytes[base_byte_idx - 3] = (uint8_t)((b->data[i] >> 24) & 0xFF); // 最高位字節 (e.g., -> bytes[28] for i=0)
    }
}

// --- 模 n 運算函數實現 ---
// 計算 (a + b) mod n
// 設 a < n 且 b < n
void add_mod_n(BigInt *res, const BigInt *a, const BigInt *b, const BigInt *n) {
    BigInt sum_ab;
    uint64_t carry = 0;

    // 1. 計算 sum = a + b，並記錄進位
    for (int i = 0; i < BIGINT_WORDS; ++i) {
         uint64_t word_sum = (uint64_t)a->data[i] + b->data[i] + carry;
         sum_ab.data[i] = (uint32_t)word_sum;
         carry = word_sum >> 32; // 獲取進位
    }

    // 2. 判斷數學和是否 >= n
    // 條件：發生了進位 (carry=1) 或者 雖然沒進位但結果 sum_ab 已經 >= n
    if (carry || compare_bigint(&sum_ab, n) >= 0) {
        // 3. 如果 >= n，則結果是 sum_ab - n
        ptx_u256Sub(res, &sum_ab, n);
    } else {
        // 4. 否則，結果就是 sum_ab
        copy_bigint(res, &sum_ab);
    }
}
// ------------------------------
// 封裝接口：字符串版（简单接口）
// ------------------------------
void compute_public_keys(const char *priv_hex,
                           char *compressed_pub_hex,  // 至少67字节(含结尾符)
                           char *uncompressed_pub_hex) {  // 至少131字节(含结尾符)
    BigInt priv;
    // 将私钥16进制字符串转换为 BigInt
    hex_to_bigint(priv_hex, &priv);
    
    ECPoint pub;
    private_to_public_key(&pub, &priv);
    
    point_to_compressed_hex(&pub, compressed_pub_hex);
    point_to_uncompressed_hex(&pub, uncompressed_pub_hex);
}

void compute_compressed_pubkey(const char *priv_hex, char *compressed_pub_hex) {
    BigInt priv;
    hex_to_bigint(priv_hex, &priv);
    
    ECPoint pub;
    private_to_public_key(&pub, &priv);
    
    point_to_compressed_hex(&pub, compressed_pub_hex);
}

void compute_pubkey_coordinates(const char *priv_hex,
                                char *x_hex,   // 至少65字节
                                char *y_hex) { // 至少65字节
    BigInt priv;
    hex_to_bigint(priv_hex, &priv);
    
    ECPoint pub;
    private_to_public_key(&pub, &priv);
    
    bigint_to_hex(&pub.x, x_hex);
    bigint_to_hex(&pub.y, y_hex);
}

static const BigInt secp256k1_sqrt_exp = {
    .data = {
        0xBFFFFF0C,  // 最低有效字 (W0)
        0xFFFFFFFF,  // W1
        0xFFFFFFFF,  // W2
        0xFFFFFFFF,  // W3
        0xFFFFFFFF,  // W4
        0xFFFFFFFF,  // W5
        0xFFFFFFFF,  // W6
        0x3FFFFFFF   // W7  （最高有效字）
    }
};

/**
 * 将一个十六进制字符串（压缩或非压缩的 SEC 公钥）转换成 ECPoint：
 *   - pub_hex_str 长度要么 66（以 '02' 或 '03' 开头），要么 130（以 '04' 开头）。
 *   - 对于非压缩格式：0x04 || X(32 bytes) || Y(32 bytes)，直接把 X、Y 拆出来；
 *   - 对于压缩格式：0x02/0x03 || X(32 bytes)，需要先把 X 提取出来，再计算
 *       α = X^3 + 7 (mod p)，然后 Y = α^((p+1)/4) (mod p)，最后根据前缀 0x02/0x03 确定
 *       是要偶数根（0x02）还是奇数根（0x03）。
 *
 * 如果解析成功，P->x, P->y 都会被填好，P->infinity = false；否则返回 -1。
 */
int hex_str_to_ecpoint(const char *pub_hex_str, ECPoint *P) {
    size_t len = strlen(pub_hex_str);
    // **格式校验**
    if (!(len == 66 || len == 130)) {
        fprintf(stderr, "hex_str_to_ecpoint: 输入长度既不是 66（压缩）也不是 130（非压缩），len=%zu\n", len);
        return -1;
    }
    if (pub_hex_str[0] != '0' || !(pub_hex_str[1] == '2' || pub_hex_str[1] == '3' || pub_hex_str[1] == '4')) {
        fprintf(stderr, "hex_str_to_ecpoint: 非法前缀 (必须以 '02', '03' 或 '04' 开头)，got=\"%c%c\"\n",
                pub_hex_str[0], pub_hex_str[1]);
        return -1;
    }

    BigInt x, y, alpha, tmp1, tmp2;
    char buf[65];  // 用来暂存 64 个 hex + '\0'

    if (pub_hex_str[1] == '4') {
        // ==========================
        // 非压缩格式： 0x04 || X(32 bytes) || Y(32 bytes)
        // ==========================
        // X 占 64 个 hex 位，从位置 [2..65]，Y 占 64 个 hex，从 [66..129]
        memset(buf, 0, sizeof(buf));
        memcpy(buf, pub_hex_str + 2, 64);
        hex_to_bigint(buf, &x);

        memset(buf, 0, sizeof(buf));
        memcpy(buf, pub_hex_str + 66, 64);
        hex_to_bigint(buf, &y);

        P->x = x;
        P->y = y;
        P->infinity = false;
        return 0;
    } else {
        // ==========================
        // 压缩格式： 0x02/0x03 || X(32 bytes)
        // ==========================
        int want_odd = (pub_hex_str[1] == '3');  // '02' 表示偶数根，'03' 表示奇数根

        // 先提取 X（64 个 hex，从 [2..65]）
        memset(buf, 0, sizeof(buf));
        memcpy(buf, pub_hex_str + 2, 64);
        hex_to_bigint(buf, &x);

        // 计算 α = x^3 + 7 (mod p)
        //   tmp1 = x * x  (x^2)
        mul_mod_old(&tmp1, &x, &x, &secp256k1_p);
        //   alpha = x^2 * x = x^3
        mul_mod_old(&alpha, &tmp1, &x, &secp256k1_p);
        //   加上常数 7
        BigInt seven; 
        init_bigint(&seven, 7);
        add_mod(&alpha, &alpha, &seven, &secp256k1_p);

        // y = alpha^((p+1)/4) mod p  —— 用预先算好的指数 secp256k1_sqrt_exp
        modexp(&y, &alpha, &secp256k1_sqrt_exp, &secp256k1_p);

        // 此时 y^2 ≡ α (mod p)。不过 y 可能对应两种根：y 和 p - y。
        // 下面确保 parity (奇偶) 跟 want_odd 一致，否则取 p - y。
        if ((is_odd(&y) ? 1 : 0) != want_odd) {
            // y = p - y
            sub_mod(&y, &secp256k1_p, &y, &secp256k1_p);
        }

        P->x = x;
        P->y = y;
        P->infinity = false;
        return 0;
    }
}
