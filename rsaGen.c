//
// Created by PetnaKanojo on 2018/8/19.
//

#include "rsaGen.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include "gmp-6.1.2/gmp.h"


#define bitN 10  // 2 ^ bitN
#define BASE 10


mpz_t * generate_rand_num() {
    mpz_t bignum1, bignum2;
    mpz_init(bignum1);
    mpz_init(bignum2);


    unsigned short seed;
    seed = time(NULL);
    gmp_randstate_t rstate;
    gmp_randinit_default(rstate);
    gmp_randseed_ui(rstate, seed);

    mpz_urandomb(bignum1, rstate, bitN);
    mpz_urandomb(bignum2, rstate, bitN);

    mpz_t * result = malloc(sizeof(mpz_t) * 2);

    mpz_init(result[0]);
    mpz_init(result[1]);


    mpz_nextprime(result[0], bignum1);
    mpz_nextprime(result[1], bignum2);

    mpz_clear(bignum1);
    mpz_clear(bignum2);
    return result;
}


mpz_t * gen_key_pair() {
    mpz_t * primes = generate_rand_num();
    mpz_t key_n, key_e, key_f;
    mpz_t p_sub, q_sub;

    mpz_inits(key_n, key_f, p_sub, q_sub, 0);
    mpz_init_set_ui(key_e, 3);   // 选取的加密密钥
    gmp_printf("key_e = %Zd\n", key_e);

    mpz_mul(key_n, primes[0], primes[1]);  // key_n = p * q
    mpz_sub_ui(p_sub, primes[0], 1);
    mpz_sub_ui(q_sub, primes[1], 1);

    mpz_mul(key_f, p_sub, q_sub);   // key_f = (p-1) * (q-1)

    gmp_printf("key_f = (p-1) * (q-1) = %Zd\n", key_f);

    mpz_t key_d;
    mpz_init(key_d);
    mpz_invert(key_d, key_e, key_f);    // 求key_e mod key_f 的逆元

    gmp_printf("test key_d= %Zd\n", key_d);

    mpz_t * result = malloc(sizeof(mpz_t) * 20);
    mpz_t mul_temp;
    mpz_init_set_ui(mul_temp, 1);
    mpz_inits(result[0], result[1], result[2], result[3], result[4], result[5], 0);
    mpz_mul(result[0], primes[0], mul_temp); // p
    mpz_mul(result[1], primes[1], mul_temp); // q
    mpz_mul(result[2], key_n, mul_temp);     // key_n = p * q;
    mpz_mul(result[3], key_d, mul_temp);     // key_d = (key_e)^(-1) mod key_f
    mpz_mul(result[4], key_f, mul_temp);     // key_f = (p-1) * (q-1)
    mpz_mul(result[5], key_e, mul_temp);     // e

    mpz_clear(primes[0]);
    mpz_clear(primes[1]);
    mpz_clear(key_n);
    mpz_clear(key_d);
    mpz_clear(key_f);
    mpz_clear(key_e);

//    for (int i = 0; i < 6; i++) {
//        gmp_printf("result[%d] = %Zd\n", i, result[i]);
//    }

    return result;

}



// 模重复平方法
void mod_exp(mpz_t result, const mpz_t exponent, const mpz_t base, const mpz_t n) {
//    gmp_printf("模重复平方法中：M = %Zd\n", base);
    char exp[2048+ 10];
    mpz_get_str(exp, 2, exponent);   // e转换为二进制
    mpz_t x, power;
    mpz_init(power);
    mpz_init_set_ui(x, 1);   // x:1
    mpz_mod(power, base, n);   // power = base mod n

    for (int i = strlen(exp) - 1; i > -1; i--) {
        if (exp[i] == '1') {
            mpz_mul(x, x, power);  // x = x * power
            mpz_mod(x, x, n);  // x = x mod n
        }
        mpz_mul(power, power, power);
        mpz_mod(power, power, n);  // power = power^2 mod n
//        gmp_printf("dddd =  %Zd\n", x);
    }
    mpz_set(result, x);
//    gmp_printf("结果 =  %Zd\n", x);
}

char * mod_Encryption(const char * plain_text, const char * key_n, mpz_t key_e) {

    mpz_t M, C, n, e;
    mpz_init_set_str(M, plain_text, 10);
    mpz_init_set_str(n, key_n, 10);
    mpz_init_set_ui(C, 0);
    mpz_t mul_temp;
    mpz_init_set_ui(mul_temp, 1);
    mpz_mul(e, key_e, mul_temp);

//    mpz_t test;
//    mpz_init_set_ui(test, 95);
    mod_exp(C, e, M, n);

    char * result = malloc(sizeof(char) * (bitN + 10));
    mpz_get_str(result, 10, C);

    return result;




//    mpz_t M, res, n, e;    mpz_get_str(exp, 2, exponent);   // e转换为二进制
//    mpz_init_set_str(M, plain_text, 10);
//
//
//    mpz_init_set_str(n, key_n, 10);
//    mpz_init_set_ui(res, 0);
//    mpz_t mul_temp;
//    mpz_init_set_ui(mul_temp, 1);
//    mpz_mul(e, key_e, mul_temp);
//
//    mpz_t test;
//    mpz_init_set_ui(test, 95);
//    mod_exp(res, e, test, n);
//
//    char * result = malloc(sizeof(char) * (bitN + 10));
//    mpz_get_str(result, 10, res);
//
//    return result;

}

char * mod_Decryption(const char * cipher_text, const char * key_n, const char * key_d) {
    mpz_t M, C, n, d;

    mpz_init_set_str(C, cipher_text, BASE);
//    gmp_printf("\n需要解码的C = %Zd\n", C);
    mpz_init_set_str(n, key_n, BASE);
//    gmp_printf("\nkey_d = %s\n", key_d);
    mpz_init_set_str(d, key_d, BASE);
    mpz_init(M);

    mod_exp(M, d, C, n);
//    gmp_printf("\nM = %Zd\n", M);
    char * result = malloc(sizeof(char) * (bitN + 10));
    mpz_get_str(result, BASE, M);

    return result;

}



void China(mpz_t result, const char * P, const char * Q, const char * X, const char * E, const char * N) {
    mpz_t p, q, x, e, n;
    mpz_t Xp, Xq, ep, eq, P1, Q1, Yp, Yq, total;
    mpz_inits(Xp, Xq, ep, eq, P1, Q1, Yp, Yq, total, NULL);

    mpz_init_set_str(p, P, BASE);
    mpz_init_set_str(q, Q, BASE);
    mpz_init_set_str(n, N, BASE);
    mpz_init_set_str(x, X, BASE);
    mpz_init_set_str(e, E, BASE);
//    printf("X = %s\n", X);

    mpz_mod(Xp, x, p);
    mpz_mod(Xq, x, q);

    mpz_sub_ui(P1, p, 1);
    mpz_sub_ui(Q1, q, 1);

    mpz_mod(ep, e, P1);
    mpz_mod(eq, e, Q1);

    mod_exp(Yp, ep, Xp, p);
    mod_exp(Yq, eq, Xq, q);

    mpz_invert(Q1, q, p);
    mpz_invert(P1, p, q);

    mpz_mul(q, Q1, q);
    mpz_mul(q, Yp, q);
    mpz_mul(p, P1, p);
    mpz_mul(p, Yp, p);
    mpz_add(total, p, q);
    mpz_mod(result, total, n);
}

char * China_Encryption(const char * plain_text, const char * key_p, const char * key_q, const char * key_n, const mpz_t key_e) {

    mpz_t M, C, n, e;
    mpz_init_set_str(M, plain_text, 10);
    mpz_init_set_str(n, key_n, 10);
    mpz_init_set_ui(C, 0);
    mpz_t mul_temp;
    mpz_init_set_ui(mul_temp, 1);
    mpz_mul(e, key_e, mul_temp);

//    mpz_t test;
//    mpz_init_set_ui(test, 95);
    mod_exp(C, e, M, n);

    char * result = malloc(sizeof(char) * (bitN + 10));
    mpz_get_str(result, 10, C);

    return result;


    // todo: CHINA
//    mpz_t res;
//    mpz_init_set_ui(res, 0);
//
//    char e_c[2048 + 10];
////    itoa(key_e, e_c, 16);
//    mpz_get_str(e_c, 16, key_e);
//
//    gmp_printf("key_e = %Zd e_c = %s\n", key_e, e_c);
////    sprintf(e_c, "%x", key_e); //将100转为16进制表示的字符串。
//    China(res, key_p, key_q, plain_text, e_c, key_n);
//
//    char * result = malloc(sizeof(char) * (bitN + 10));
//    mpz_get_str(result, BASE, res);
//    return result;
}

void montgomery(mpz_t res, const char * base, const char * exponent, const char * n) {
    mpz_t A, B, N, D;
    mpz_t temp;
    mpz_init_set_ui(temp, 0);
    mpz_init_set_str(A, base, BASE);
    mpz_init_set_str(B, exponent, BASE);
    mpz_init_set_str(N, n, BASE);
    mpz_init_set_ui(D, 1);

    while (mpz_cmp_ui(B, 0)) {
        if (mpz_odd_p(B)) {
            mpz_mul(temp, D, A);
            mpz_mod(D, temp, N);
            mpz_sub_ui(B, B, 1);
        } else {
            mpz_pow_ui(temp, A, 2);
            mpz_mod(A, temp, N);
            mpz_divexact_ui(B, B, 2);
        }
    }
    mpz_set(res, D);
}

char * mont_encrypt(const char * plain_text, const char * key_n, mpz_t key_e) {
    mpz_t e;
    mpz_t x, n, res;

    mpz_init(res);
    mpz_init_set_str(x, plain_text, BASE);
    mpz_init_set_str(n, key_n, BASE);
//    mpz_init_set_ui(e, key_e);

    char e_c[2048+10];
    mpz_get_str(e_c, 16, key_e);

    montgomery(res, plain_text, e_c, key_n);

    char * result = malloc(sizeof(char) * (bitN + 10));
    mpz_get_str(result, BASE, res);

    return result;
}

char * mont_decrypt(const char * cipher_text, const char * key_n, const char * key_d) {
    mpz_t M;
    mpz_init(M);

    montgomery(M, cipher_text, key_d, key_n);

    char * result = malloc(sizeof(char) * (bitN + 10));
    mpz_get_str(result, BASE, M);

    return result;
}

int main (void) {
    mpz_t * num_arr = malloc(sizeof(mpz_t) * 2);

    mpz_t * result = gen_key_pair();

    mpz_t key_p, key_q, key_n, key_fayN, key_e, key_d;
    mpz_inits(key_p, key_q, key_n, key_fayN, key_e, key_d, 0);
    mpz_t mul_temp;
    mpz_init_set_ui(mul_temp, 1);
    mpz_mul(key_p, result[0], mul_temp);
    mpz_mul(key_q, result[1], mul_temp);
    mpz_mul(key_n, result[2], mul_temp);
    mpz_mul(key_d, result[3], mul_temp);
    mpz_mul(key_fayN, result[4], mul_temp);
    mpz_mul(key_e, result[5], mul_temp);
    // 打印 RSA算法的参数
    gmp_printf("p = %Zd\n", key_p);
    gmp_printf("q = %Zd\n", key_q);
    gmp_printf("n = %Zd\n", key_n);
    gmp_printf("fayN = %Zd\n", key_fayN);
    gmp_printf("d = %Zd\n", key_d);
    gmp_printf("e = %Zd\n", key_e);

    char * buf_n = malloc(sizeof(bitN + 10));
    char * buf_p = malloc(sizeof(bitN + 10));
    char * buf_q = malloc(sizeof(bitN + 10));
    char * buf_d = malloc(sizeof(bitN + 10));
    char * buf_fayN = malloc(sizeof(bitN + 10));

    mpz_get_str(buf_n, 10, key_n);
    mpz_get_str(buf_d, 10, key_d);
    mpz_get_str(buf_p, 10, key_p);
    mpz_get_str(buf_q, 10, key_q);
    mpz_get_str(buf_fayN, 10, key_fayN);

    printf("buf_d = %s\n", buf_d);
    char plain_text[20];
    strcpy(plain_text, "87");
    printf("main function plain_text = %s\n", plain_text);
    char * mod_result = mod_Encryption(plain_text, buf_n, key_e);
    gmp_printf("in main function: (mod encryption of M) is %s\n", mod_result);
    char * mod_decryption_res = mod_Decryption(mod_result, buf_n, buf_d);
    gmp_printf("in main function: (mod encryption of C) is %s\n", mod_decryption_res);
//    printf("mod_result = %s", mod_result);
    strcpy(plain_text, "87");
//    printf("main function plain_text = %s\n", plain_text);
    char * china_result = China_Encryption(plain_text, buf_p, buf_q, buf_n, key_e);
    gmp_printf("in main function: (china encryption of C) is %s\n", china_result);

    strcpy(plain_text, "87");
    char * mont_result = mont_encrypt(plain_text, buf_n, key_e);
    gmp_printf("in main function: (mont encryption of C) is %s\n", mont_result);
    char * mont_decryption_res = mont_decrypt(mont_result, buf_n, buf_d);
    gmp_printf("in main function: (mod decryption of C) is %s\n", mont_decryption_res);

    return 0;
}