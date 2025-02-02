#include <stdio.h>
#include <gmp.h>
#include "ecc.h"

int main(void) {
    // 初始化椭圆曲线参数（以 secp256k1 为例）
    EllipticCurve curve;
    mpz_inits(curve.p, curve.a, curve.b, curve.n, NULL);
    // secp256k1 素数 p = 2^256 - 2^32 - 977
    mpz_set_str(curve.p, "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);
    // 对于 secp256k1，a = 0, b = 7
    mpz_set_ui(curve.a, 0);
    mpz_set_ui(curve.b, 7);
    // 基点阶 n（此处仅用于参考）
    mpz_set_str(curve.n, "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
    
    // 初始化基点 G（sec256k1 的 G 点）
    Point G;
    point_init(&G);
    mpz_set_str(G.x, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16);
    mpz_set_str(G.y, "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
    G.infinity = 0;
    
    // 测试：计算 R = 2 * G（理论上应等于点倍加 G）
    mpz_t k;
    mpz_init_set_str(k, "2", 10);
    
    Point R;
    point_init(&R);
    
    scalar_multiplication(&curve, &G, &R, k);
    
    printf("2 * G:\n");
    gmp_printf("R.x = %Zx\n", R.x);
    gmp_printf("R.y = %Zx\n", R.y);
    
    // 清理资源
    point_clear(&G);
    point_clear(&R);
    mpz_clears(curve.p, curve.a, curve.b, curve.n, k, NULL);
    
    return 0;
}

