/*
 * Copyright (c) 2021, Luis Alberto
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "ecc.h"
#include <stdlib.h>

/* --------------------
   点的初始化、释放、复制等辅助函数
   -------------------- */

// 初始化点（对内部 mpz_t 变量进行初始化，并将其标记为无穷远点）
void point_init(Point *P) {
    mpz_init(P->x);
    mpz_init(P->y);
    P->infinity = 1; // 默认设置为无穷远点
}

// 释放点（清除 mpz_t 变量）
void point_clear(Point *P) {
    mpz_clear(P->x);
    mpz_clear(P->y);
}

// 将 src 复制到 dest
void point_copy(Point *dest, const Point *src) {
    mpz_set(dest->x, src->x);
    mpz_set(dest->y, src->y);
    dest->infinity = src->infinity;
}

// 将点设置为无穷远点
void point_set_infinity(Point *P) {
    mpz_set_ui(P->x, 0);
    mpz_set_ui(P->y, 0);
    P->infinity = 1;
}

// 判断点是否为无穷远点
int point_is_infinity(const Point *P) {
    return P->infinity;
}

/* --------------------
   椭圆曲线运算
   -------------------- */

/* 点倍加： R = 2*P
   公式：λ = (3*x^2 + a) / (2*y)  mod p
         x_R = λ^2 − 2*x  mod p
         y_R = λ*(x − x_R) − y  mod p
*/
void point_doubling(const EllipticCurve *EC, const Point *P, Point *R) {
    if (point_is_infinity(P)) {
        point_set_infinity(R);
        return;
    }
    // 当 y == 0 时，切线垂直于 x 轴，结果为无穷远
    if (mpz_cmp_ui(P->y, 0) == 0) {
        point_set_infinity(R);
        return;
    }
    
    mpz_t slope, temp, inv;
    mpz_inits(slope, temp, inv, NULL);
    
    // 计算分子：3*x^2 + a
    mpz_mul(temp, P->x, P->x);      // temp = x^2
    mpz_mul_ui(temp, temp, 3);       // temp = 3*x^2
    mpz_add(temp, temp, EC->a);      // temp = 3*x^2 + a
    
    // 计算分母：2*y
    mpz_mul_ui(inv, P->y, 2);
    mpz_invert(inv, inv, EC->p);     // inv = (2*y)^(-1) mod p
    
    // slope = (3*x^2 + a) / (2*y)
    mpz_mul(slope, temp, inv);
    mpz_mod(slope, slope, EC->p);
    
    // 计算 x 坐标：x_R = slope^2 - 2*x
    mpz_mul(R->x, slope, slope);    // R->x = slope^2
    mpz_submul_ui(R->x, P->x, 2);     // R->x = slope^2 - 2*x
    mpz_mod(R->x, R->x, EC->p);
    
    // 计算 y 坐标：y_R = slope*(x - x_R) - y
    mpz_sub(temp, P->x, R->x);      // temp = x - x_R
    mpz_mul(R->y, slope, temp);     // R->y = slope*(x - x_R)
    mpz_sub(R->y, R->y, P->y);      // R->y = slope*(x - x_R) - y
    mpz_mod(R->y, R->y, EC->p);
    
    R->infinity = 0;
    mpz_clears(slope, temp, inv, NULL);
}

/* 点加法： R = P + Q
   若 P 或 Q 为无穷远，则结果为另一点；
   若 P == Q，则调用点倍加；
   否则，公式：λ = (Q->y - P->y) / (Q->x - P->x) mod p，
           x_R = λ^2 - P->x - Q->x mod p，
           y_R = λ*(P->x - x_R) - P->y mod p  */
void point_addition(const EllipticCurve *EC, const Point *P, const Point *Q, Point *R) {
    if (point_is_infinity(P)) {
        point_copy(R, Q);
        return;
    }
    if (point_is_infinity(Q)) {
        point_copy(R, P);
        return;
    }
    
    // 若 P 与 Q 在 x 坐标相等
    if (mpz_cmp(P->x, Q->x) == 0) {
        mpz_t temp;
        mpz_init(temp);
        mpz_add(temp, P->y, Q->y);
        mpz_mod(temp, temp, EC->p);
        // 如果 y_P + y_Q ≡ 0 (mod p)，则 P = -Q，和为无穷远
        if (mpz_cmp_ui(temp, 0) == 0) {
            mpz_clear(temp);
            point_set_infinity(R);
            return;
        }
        mpz_clear(temp);
        // 否则 P == Q，使用倍加
        point_doubling(EC, P, R);
        return;
    }
    
    mpz_t slope, temp, inv;
    mpz_inits(slope, temp, inv, NULL);
    
    // slope = (Q->y - P->y) / (Q->x - P->x)
    mpz_sub(temp, Q->y, P->y);      // temp = Q->y - P->y
    mpz_sub(inv, Q->x, P->x);       // inv = Q->x - P->x
    mpz_invert(inv, inv, EC->p);    // inv = (Q->x - P->x)^(-1)
    mpz_mul(slope, temp, inv);      // slope = (Q->y - P->y) / (Q->x - P->x)
    mpz_mod(slope, slope, EC->p);
    
    // x_R = slope^2 - P->x - Q->x
    mpz_mul(R->x, slope, slope);
    mpz_sub(R->x, R->x, P->x);
    mpz_sub(R->x, R->x, Q->x);
    mpz_mod(R->x, R->x, EC->p);
    
    // y_R = slope*(P->x - x_R) - P->y
    mpz_sub(temp, P->x, R->x);
    mpz_mul(R->y, slope, temp);
    mpz_sub(R->y, R->y, P->y);
    mpz_mod(R->y, R->y, EC->p);
    
    R->infinity = 0;
    mpz_clears(slope, temp, inv, NULL);
}

/* 标量乘法： R = m * P
   使用从最高位到最低位的“双倍加法”算法 */
void scalar_multiplication(const EllipticCurve *EC, const Point *P, Point *R, const mpz_t m) {
    // 初始化 R 为无穷远点
    point_set_infinity(R);
    
    // 用一个临时点 Q 保存 P 的拷贝
    Point Q;
    point_init(&Q);
    point_copy(&Q, P);
    
    size_t nbits = mpz_sizeinbase(m, 2);
    
    // 从最高有效位到最低位遍历
    for (ssize_t i = nbits - 1; i >= 0; i--) {
        // R = 2*R
        if (!point_is_infinity(R)) {
            Point temp;
            point_init(&temp);
            point_doubling(EC, R, &temp);
            point_copy(R, &temp);
            point_clear(&temp);
        }
        // 如果当前位为 1，则 R = R + Q
        if (mpz_tstbit(m, i)) {
            if (point_is_infinity(R)) {
                point_copy(R, &Q);
            } else {
                Point temp;
                point_init(&temp);
                point_addition(EC, R, &Q, &temp);
                point_copy(R, &temp);
                point_clear(&temp);
            }
        }
    }
    
    point_clear(&Q);
}

/* 点取反： R = -P，即 R->y = p - P->y，x 保持不变 */
void point_negation(const EllipticCurve *EC, const Point *P, Point *R) {
    if (point_is_infinity(P)) {
        point_set_infinity(R);
        return;
    }
    point_copy(R, P);
    mpz_sub(R->y, EC->p, R->y);
    R->infinity = 0;
}

