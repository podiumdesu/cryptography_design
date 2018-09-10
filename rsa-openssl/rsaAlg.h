//
// Created by PetnaKanojo on 2018/8/29.
//

#ifndef CRYPTOGRAPHY_RSAALG_H
#define CRYPTOGRAPHY_RSAALG_H
int Mod_inverse(BIGNUM *a, BIGNUM *b, BIGNUM *x, BIGNUM *y);  //����
void RSAGeneratePara();                                       //RSA��������
void RSADisplayPara();                                  //RSA���������������
void chinaAlg();                                               //�й�ʣ�ඨ��
void modRepeatAlg();                                      //ģ�ظ�ƽ��
void montAlg();                                           //�ɸ������㷨
void reduce(BIGNUM* s, BIGNUM* x, BIGNUM* r, BIGNUM* p, BIGNUM* n);
void freeAllBigNum(void);
#endif //CRYPTOGRAPHY_RSAALG_H


