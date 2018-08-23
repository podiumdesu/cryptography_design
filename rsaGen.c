//
// Created by PetnaKanojo on 2018/8/19.
//

#include "rsaGen.h"
#include <time.h>
#include <stdlib.h>
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

    gmp_printf("key_d= %Zd\n", key_d);

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

    for (int i = 0; i < 6; i++) {
        gmp_printf("result[%d] = %Zd\n", i, result[i]);
    }

    return result;

}



// 模重复平方法
void mod_exp(mpz_t result, const mpz_t exponent, const mpz_t base, const mpz_t n) {
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
    }
    mpz_set(result, x);
    gmp_printf("x = %Zd\n", x);
}

char * mod_Encryption(const char * plain_text, const char * key_n, mpz_t key_e) {
    mpz_t M, res, n, e;
    mpz_init_set_str(M, plain_text, 10);


    mpz_init_set_str(n, key_n, 10);
    mpz_init_set_ui(res, 0);
    mpz_t mul_temp;
    mpz_init_set_ui(mul_temp, 1);
    mpz_mul(e, key_e, mul_temp);

    mpz_t test;
    mpz_init_set_ui(test, 95);
    mod_exp(res, e, test, n);

    char * result = malloc(sizeof(char) * (bitN + 10));
    mpz_get_str(result, 10, res);

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

    char plain_text[20];
    strcpy(plain_text, "hello,world");
    mod_Encryption(plain_text, buf_n, key_e);

//    printf("mod_result = %s", mod_result);

    return 0;
}