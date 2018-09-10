//
// Created by PetnaKanojo on 2018/8/29.
//

#ifndef CRYPTOGRAPHY_OVERALL_H
#define CRYPTOGRAPHY_OVERALL_H

extern BIGNUM* p;
extern BIGNUM* q;                                      //����˽Կ
extern BIGNUM* psub;
extern BIGNUM* qsub;                                //psub=p-1,qsub=q-1
extern BIGNUM* dp;
extern BIGNUM* dq;                                        //dp=d mod p-1,dq=d mod q-1
extern BIGNUM* mp;
extern BIGNUM* mq;                                        //q*mq+p*mp=1,mp��mq�ֱ���qģp��pģq����,mp= q^-1 mod p
extern BIGNUM* fain;                                      //fain=(p-1)(q-1)
extern BIGNUM* n;
extern BIGNUM* m;
extern BIGNUM* d;
extern BIGNUM* e;
extern BIGNUM* r;
extern BIGNUM* x;                                         //����
extern BIGNUM* y;                                         //����
extern BIGNUM* mpq;
extern BIGNUM* mqp;                                       //mpq=mp*q, mqp=mq*p
extern BIGNUM* m1;
extern BIGNUM* m2;                                        //m1=y^dp mod p, m2=y^dq mod q
extern BIGNUM* a;
extern BIGNUM* b;
extern BIGNUM* x0;
extern BIGNUM* one;
extern BIGNUM* zero;
extern BIGNUM* two;
extern BIGNUM* temp1;
extern BIGNUM* temp2;
extern BIGNUM* a0;
extern BIGNUM* b0;
extern BIGNUM* nn;
extern BIGNUM* n0;
extern BIGNUM* bb;
extern BN_CTX* ctx;

#endif //CRYPTOGRAPHY_OVERALL_H