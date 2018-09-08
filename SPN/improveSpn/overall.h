//
// Created by PetnaKanojo on 2018/9/8.
//

#ifndef CRYPTOGRAPHY_OVERALL_H
#define CRYPTOGRAPHY_OVERALL_H
#define Nr 16



extern int  S[16][16];                     //AES代换
extern int Pbox[16];      //
extern int  S_inverse[16][16];
extern long long key[Nr+1];
extern long long w;
extern long long u;
extern long long v;
extern int max;//10M
extern unsigned long long k1;
extern unsigned long long k2;
extern unsigned long long x1;
extern unsigned long long x2;
extern unsigned long long iv1;
extern unsigned long long iv2;


#endif //CRYPTOGRAPHY_OVERALL_H
