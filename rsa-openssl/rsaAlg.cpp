#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "overall.h"
#include "rsaAlg.h"

/**********************求逆*********************/
int Mod_inverse(BIGNUM *a, BIGNUM *b, BIGNUM *x, BIGNUM *y) {
    BIGNUM* a1 = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (BN_is_zero(b)) {
        BN_dec2bn(&x, "1");
        BN_dec2bn(&y, "0");
    }
    else {
        BN_mod(a1, a, b, ctx);   //a=a%b
        Mod_inverse(b, a1, x, y);
        BIGNUM *temp = BN_new();
        BIGNUM* r = BN_new();
        BIGNUM* c = BN_new();
        BN_copy(temp, x);
        BN_copy(x, y);
        BN_div(r, c, a, b, ctx);
        BN_mul(r, r, y, ctx);    //r=a/b*y
        BN_sub(y, temp, r);
        BN_free(r);
        BN_free(c);
        BN_free(temp);
    }
    BN_CTX_free(ctx);
    BN_free(a1);
    return 0;
}
/**********************求逆*********************/

/******************RSA素数生成******************/
/*
 * 函数名：RSAGeneratePara()
 * 用 途：生成参数
 */
void RSAGeneratePara() {
    BN_generate_prime(p, 512, 0, 0, 0, 0, 0); //生成一个512bit的素数
    BN_generate_prime(q, 512, 0, 0, 0, 0, 0);
    BN_copy(psub, p);
    BN_copy(qsub, q);
    BN_sub_word(psub, 1);                    //psub=p-1
    BN_sub_word(qsub, 1);                    //qsub=q-1
    BN_mul(fain, psub, qsub, ctx);           //n=(p-1)(q-1)
    BN_dec2bn(&e, "65537");                  //e=65537
    Mod_inverse(e, fain, d, r);              //求逆  (d*e)^(-1) = 1(mod)fain
    if (BN_cmp(0, d) == 1) {
        BN_add(d, d, fain);
    }
}

/*
 * 函数名：RSADisplayPara()
 * 用 途：通过转换为十进制来显示大素数
 */
void RSADisplayPara(){
    char* cn, *ce, *cd, *cp, *cq;
    RSAGeneratePara();
    BN_mul(n, p, q, ctx);     // n=pq
    cn = BN_bn2dec(n);        // n 转换为10进制字符串
    ce = BN_bn2dec(e);
    cd = BN_bn2dec(d);
    cp = BN_bn2dec(p);
    cq = BN_bn2dec(q);
    printf("n = \n%s\n\n", cn);
    printf("e = \n%s\n\n", ce);
    printf("p = \n%s\n\n", cp);
    printf("q = \n%s\n\n", cq);
    printf("d = \n%s\n\n", cd);
    printf("\nRSA参数生成完毕\n\n");
}
/******************RSA素数生成******************/

/******************中国剩余定理******************/
void chinaAlg()   {
    RSAGeneratePara();         // 参数生成
    BN_rand(x, 936, 0, 0);
    // x=y^d mod n
    BN_mul(n, p, q, ctx);		    //n=p*q
    BN_mod_exp(y, x, e, n, ctx);	//y=x^e mod n
    BN_mod(dp, d, psub, ctx);	    //dp=d mod p-1
    BN_mod(dq, d, qsub, ctx);		//dq=d mod q-1
    BN_mod_exp(m1, y, dp, p, ctx);	//m1=y^dp mod p
    BN_mod_exp(m2, y, dq, q, ctx);	//m2=y^dq mod q
    Mod_inverse(p, q, mq, mp);     //q*mq+p*mp=1,mp= q^-1 mod p
    if (BN_cmp(0, mp) == 1) {
        BN_add(mp, mp, p);
    }
    if (BN_cmp(0, mq) == 1) {
        BN_add(mq, mq, q);
    }
    BN_mul(mpq, mp, q, ctx);	           //mpq= mp*q
    BN_mul(mqp, mq, p, ctx);		       //mqp= mq*p
    BN_mul(temp1, mpq, m1, ctx);		   //temp1=mpq*m1
    BN_mul(temp2, mqp, m2, ctx);		   //temp2=mqp*m2
    BN_mod_add(x0, temp1, temp2, n, ctx);  //x3=mp*q*m1+mq*q*m2 mod n
    char* cx = BN_bn2dec(x);
    char* cy = BN_bn2dec(y);
    char* cx0 = BN_bn2dec(x0);
    printf("中国剩余定理加解密结果：\n\n");
    printf("加密明文x=\n%s\n\n", cx);
    printf("加密密文y=\n%s\n\n", cy);
    printf("\n\n");
    printf("解密得明文x0=\n%s\n", cx0);
    printf("中国剩余定理加解密完成\n");
}
/******************中国剩余定理******************/

/******************模重复平方******************/
void modRepeatAlg()   {
    RSAGeneratePara();
    BN_rand(x, 936, 0, 0);
    BN_mul(n, p, q, ctx);	   //n=p*q
    BN_mod_exp(y, x, e, n, ctx);   //y=x^e mod n

    // 解密过程
    BN_set_word(a0, 1);
    BN_copy(n0, d);
    BN_copy(b0, y);
    BN_copy(m, n);
    do {
        BN_div(r, nn, n0, two, ctx);    //r=n0/2,nn=n0%2
        if (BN_is_one(nn))
            BN_mod_mul(a, a0, b0, m, ctx);    //a=a0*b0 mod m
        else   BN_copy(a, a0);                //a=a0
        BN_mod_sqr(bb, b0, m, ctx);      //bb=b0*b0 mod m
        BN_copy(n0, r);                     //n0=r=n0/2
        BN_copy(a0, a);
        BN_copy(b0, bb);
    } while (!BN_is_zero(r));
    BN_copy(x0, a);
    char* cx = BN_bn2dec(x);
    char* cy = BN_bn2dec(y);
    char* cx0 = BN_bn2dec(x0);
    printf("模重复平方算法加解密结果\n\n");
    printf("加密明文x=\n%s\n\n", cx);
    printf("加密密文y=\n%s\n\n", cy);
    printf("\n\n");
    printf("解密得明文x0=\n%s\n", cx0);
    printf("模重复平方算法加解密完成\n");
}
/******************模重复平方******************/

/****************蒙哥马利算法******************/
void montAlg(){
    RSAGeneratePara();
    BN_rand(x, 936, 0, 0);   // 加密用的随机数
    BN_mul(n, p, q, ctx);		     //n=p*q
    BN_mod_exp(y, x, e, n, ctx);	 //y=x^e mod n

    int m;
    BN_dec2bn(&r, "4294967296");
    for (m = 0; BN_cmp(r, n) != 1; m++)
        BN_mul(r, r, two, ctx);
    Mod_inverse(r, n, mp, n0);       //mp=r^-1 mod n, n0=n^-1 mod r
    BN_sub(n0, zero, n0);
    BN_copy(a, y);
    BN_copy(b, d);
    BN_mod_mul(d, one, r, n, ctx);
    BN_mod_mul(a, a, r, n, ctx);
    do {
        BN_div(bb, temp1, b, two, ctx);
        if (BN_is_one(temp1)) {
            BN_mul(temp2, d, a, ctx);
            reduce(d, temp2, r, n, n0);
        }
        BN_mod_mul(temp2, a, a, n, ctx);
        reduce(a, temp2, r, n, n0);
        BN_copy(b, bb);
    } while (!BN_is_zero(b));
    BN_mod_mul(x0, d, mp, n, ctx);
    char* cx = BN_bn2dec(x);
    char* cy = BN_bn2dec(y);
    char* cx0 = BN_bn2dec(x0);
    printf("蒙哥马利算法加解密结果：\n\n");
    printf("加密明文x=\n%s\n\n", cx);
    printf("加密密文y=\n%s\n\n", cy);
    printf("\n\n");
    printf("解密得明文x0=\n%s\n", cx0);
    printf("蒙哥马利算法加解密完成！\n");
}
void reduce(BIGNUM* s, BIGNUM* x, BIGNUM* r, BIGNUM* p, BIGNUM* n) {
    BIGNUM *a = BN_new();
    BIGNUM *q = BN_new();

    //q = (x % r) * n % r;
    BN_mod(temp1, x, r, ctx);
    BN_mod_mul(q, temp1, n, r, ctx);

    //a = (x + q * p) % r;
    BN_mul(temp1, q, p, ctx);
    BN_add(temp2, temp1, x);
    BN_div(a, NULL, temp2, r, ctx);
    if (BN_cmp(a, p) == 1) {
        BN_sub(s, a, p);
    } else {
        BN_copy(s, a);
    }
}
/****************蒙哥马利算法******************/


void freeAllBigNum(void) {     // 释放所有大数空间
    BN_free(p);
    BN_free(q);
    BN_free(psub);
    BN_free(qsub);
    BN_free(dp);
    BN_free(dq);
    BN_free(mp);
    BN_free(mq);
    BN_free(fain);
    BN_free(n);
    BN_free(m);
    BN_free(d);
    BN_free(e);
    BN_free(r);
    BN_free(x);
    BN_free(y);
    BN_free(mpq);
    BN_free(mqp);
    BN_free(m1);
    BN_free(m2);
    BN_free(a);
    BN_free(b);
    BN_free(x0);
    BN_free(one);
    BN_free(zero);
    BN_free(two);
    BN_free(temp1);
    BN_free(temp2);
    BN_free(a0);
    BN_free(b0);
    BN_free(nn);
    BN_free(n0);
    BN_free(bb);
    BN_CTX_free(ctx);
}


