
// Created by PetnaKanojo on 2018/9/1.
//

#ifndef CRYPTOGRAPHY_IMPROVESPN_H
#define CRYPTOGRAPHY_IMPROVESPN_H
#define Nr 16


/************************转换**************************/
long long bit64ToNum(int  bit[64]);        //
void numTo64Bit(int  bit[64],long long u); //
int  bit16ToNum(int  bit[16]);              //
void numTo16Bit(int  bit[16],int u);        //
long long charToHex(char x_128[32],int m);//
/************************转换**************************/

/**********************增强加密‹*************************/
long long substitutionChange (long long u,int S[16][16]);//加、解密S盒子替代
long long permutationChange (long long u);              //加密P盒子置换
long long previousPChange(int  u);                        //原始spn的16bit置换、用于permutationChange中
long long spn_encode(long long x,long long K);
/**********************增强加密‹*************************/

/**********************增强解密‹*************************/
void substitutionReverseChange(int S[16][16],int S_inverse[16][16]);//解密时所用的S盒逆编排
long long permutationReverseChange (long long u);                     //解密P盒子逆置换
long long spn_decode(long long y,long long K);
/**********************增强解密*************************/

/************************密钥编排**************************/
unsigned long long KL_LShift(unsigned long long KL,int t); //密钥编排时KL循环左移
unsigned long long KR_LShift(unsigned long long KR,int t); //密钥编排时KR循环左移
void KEY_Arr (long long K,long long key[Nr+1]);          //密钥编排方案

/************************密钥编排**************************/


#endif //CRYPTOGRAPHY_IMPROVESPN_H
