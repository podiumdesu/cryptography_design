//
// Created by PetnaKanojo on 2018/8/19.
//

#include "rsaGen.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "gmp-6.1.2/gmp.h"


#define bitN 10  // 2 ^ bitN

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

    gmp_printf("result0 = %Zd\n", result[0]);
    gmp_printf("result1 = %Zd\n", result[1]);
//    gmp_printf("resultdd0 = %Zd\n", bignum1);
//    gmp_printf("resultdd1 = %Zd\n", bignum2);
    mpz_clear(bignum1);
    mpz_clear(bignum2);
    return result;
}


mpz_t * gen_key_pair() {
    mpz_t * primes = generate_rand_num();
    mpz_t key_n, key_e, key_f;
    mpz_t p_sub, q_sub;

    mpz_inits(key_n, key_f, p_sub, q_sub, 0);
    mpz_init_set_ui(key_e, 65537);   // 选取的加密密钥
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
    mpz_init_set_ui(key_e, 65537);   // 选取的加密密钥
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

//    char * buf_p = malloc(sizeof(char) * (bitN + 10));
//    char * buf_q = malloc(sizeof(char) * (bitN + 10));
//    char * buf_n = malloc(sizeof(char) * (bitN + 10));
//    char * buf_d = malloc(sizeof(char) * (bitN + 10));
//    char * buf_f = malloc(sizeof(char) * (bitN + 10));
//
//
//    mpz_get_str(buf_p, BASE, primes[0]);
//    result
//    mpz_get_str(buf_q, BASE, primes[1]);


}

int main (void) {
    mpz_t * num_arr = malloc(sizeof(mpz_t) * 2);
    // 生成 p q;
//    memcpy(num_arr, generate_rand_num(), (sizeof(mpz_t) * 2));
//    gmp_printf("p = %Zd\n", num_arr[0]);
//    gmp_printf("q = %Zd\n", num_arr[1]);
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


    return 0;
}