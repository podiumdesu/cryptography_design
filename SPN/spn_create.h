//
// Created by PetnaKanojo on 2018/8/6.
//

#ifndef CRYPTOGRAPHY_SPN_CREATE_H
#define CRYPTOGRAPHY_SPN_CREATE_H


void putBitIntoArr(unsigned int *, unsigned int);
// S盒子 逆
unsigned int substitutionReverseChange(unsigned int input);

// spn加密明文x，输出
unsigned int spn_create(unsigned int, unsigned long);
unsigned int spn_decode(unsigned int, unsigned long);
unsigned int spn_linear_analysis(unsigned int);
unsigned int spn_diff_analysis(unsigned int);

int getKeyStringBlockLength(unsigned long keyString);
#endif //CRYPTOGRAPHY_SPN_CREATE_H
