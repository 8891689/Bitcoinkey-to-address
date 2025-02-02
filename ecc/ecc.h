// ecc.h

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
#ifndef ECC_H
#define ECC_H

#include <gmp.h>

typedef struct Point {
    mpz_t x;
    mpz_t y;
    int infinity;  // 0 表示普通点，1 表示无穷远点
} Point;

typedef struct Elliptic_Curve {
    mpz_t p;
    mpz_t a;
    mpz_t b;
    mpz_t n;
} EllipticCurve;

void point_init(Point *P);
void point_clear(Point *P);
void point_copy(Point *dest, const Point *src);
void point_set_infinity(Point *P);
int point_is_infinity(const Point *P);

void point_doubling(const EllipticCurve *EC, const Point *P, Point *R);
void point_addition(const EllipticCurve *EC, const Point *P, const Point *Q, Point *R);
void scalar_multiplication(const EllipticCurve *EC, const Point *P, Point *R, const mpz_t m);
void point_negation(const EllipticCurve *EC, const Point *P, Point *R);

#endif /* ECC_H */

