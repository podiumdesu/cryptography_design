//
// Created by PetnaKanojo on 2018/8/29.
//

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "overall.h"

BIGNUM * p = BN_new();
BIGNUM * q = BN_new();
BIGNUM * psub = BN_new();
BIGNUM * qsub = BN_new();    //psub=p-1,qsub=q-1
BIGNUM * dp = BN_new();
BIGNUM * dq = BN_new();      //dp=d mod p-1,dq=d mod q-1
BIGNUM * mp = BN_new();
BIGNUM * mq = BN_new();      //q*mq+p*mp=1,mp��mq�ֱ���qģp��pģq����,mp= q^-1 mod p
BIGNUM * fain = BN_new();    //fain=(p-1)(q-1)
BIGNUM * n = BN_new();
BIGNUM * m = BN_new();
BIGNUM * d = BN_new();
BIGNUM * e = BN_new();
BIGNUM * r = BN_new();
BIGNUM * x = BN_new();   // 明文
BIGNUM * y = BN_new();   // 密文
BIGNUM * mpq = BN_new();
BIGNUM * mqp = BN_new();     //mpq=mp*q, mqp=mq*p
BIGNUM * m1 = BN_new();
BIGNUM * m2 = BN_new();      //m1=y^dp mod p, m2=y^dq mod q
BIGNUM * a = BN_new();
BIGNUM * b = BN_new();
BIGNUM * x0 = BN_new();
BIGNUM * one = BN_new();
BIGNUM * zero = BN_new();
BIGNUM * two = BN_new();
BIGNUM * temp1 = BN_new();
BIGNUM * temp2 = BN_new();
BIGNUM * a0 = BN_new();
BIGNUM * b0 = BN_new();
BIGNUM * nn = BN_new();
BIGNUM * n0 = BN_new();
BIGNUM * bb = BN_new();
BN_CTX * ctx = BN_CTX_new();
