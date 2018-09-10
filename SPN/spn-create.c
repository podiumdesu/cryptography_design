//
// Created by PetnaKanojo on 2018/8/2.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#define KEYScheduleRound 5

#include "spn_create.h"

int KEYScheduleRound = 0;

void putBitIntoArr (unsigned int * desArr, unsigned int ori) {
    // 暂定是16位的。
    for (int i = 15; i >= 0; i--) {
        desArr[i] = ori & 0x0001;
        ori >>= 1;
    }
}

// S盒子
unsigned int substitutionBox(int input) {
   switch(input) {
       case 0: return 0xe;
       case 1: return 0x4;
       case 2: return 0xd;
       case 3: return 0x1;
       case 4: return 0x2;
       case 5: return 0xf;
       case 6: return 0xb;
       case 7: return 0x8;
       case 8: return 0x3;
       case 9: return 0xa;
       case 10: return 0x6;
       case 11: return 0xc;
       case 12: return 0x5;
       case 13: return 0x9;
       case 14: return 0x0;
       case 15: return 0x7;
       default: return 0x0;
   }
}

unsigned int substitutionReverseBox(unsigned int input) {
    switch(input) {
        case 0: return 0xe;
        case 1: return 0x3;
        case 2: return 0x4;
        case 3: return 0x8;
        case 4: return 0x1;
        case 5: return 0xc;
        case 6: return 0xa;
        case 7: return 0xf;
        case 8: return 0x7;
        case 9: return 0xd;
        case 10: return 0x9;
        case 11: return 0x6;
        case 12: return 0xb;
        case 13: return 0x2;
        case 14: return 0x0;
        case 15: return 0x5;
        default: return 0x0;
    }
}


unsigned int substitutionReverseChange(unsigned int input) {
    // 确定是16位的。
    unsigned int block1 = (0xf000 & input) >> 12;   // 0001 0000 0000 0000
    unsigned int block2 = (0x0f00 & input) >> 8;   // 0000 1100 0000 0000
    unsigned int block3 = (0x00f0 & input) >> 4;   // 0000 0000 0010 0000
    unsigned int block4 = (0x000f & input) >> 0;   // 0000 0000 0000 0011
    block1 = substitutionReverseBox(block1) << 12;
    block2 = substitutionReverseBox(block2) << 8;
    block3 = substitutionReverseBox(block3) << 4;
    block4 = substitutionReverseBox(block4) << 0;
    return block1 | block2 | block3 | block4;
}
// S盒子代换
unsigned int substitutionChange(unsigned int input) {   // 输入0b 0001 1100 0010 0011
    // 确定是16位的。
    unsigned int block1 = (0xf000 & input) >> 12;   // 0001 0000 0000 0000
    unsigned int block2 = (0x0f00 & input) >> 8;   // 0000 1100 0000 0000
    unsigned int block3 = (0x00f0 & input) >> 4;   // 0000 0000 0010 0000
    unsigned int block4 = (0x000f & input) >> 0;   // 0000 0000 0000 0011
    block1 = substitutionBox(block1) << 12;
    block2 = substitutionBox(block2) << 8;
    block3 = substitutionBox(block3) << 4;
    block4 = substitutionBox(block4) << 0;
    return block1 | block2 | block3 | block4;
}


unsigned int xorChange(unsigned int input, unsigned int key) {
    return input ^ key;
}

int getKeyStringBlockLength (unsigned long keyString) {
    int i = 0;
    while (keyString > 0) {
        keyString >>= 4;
        i++;
    }
    return i;
}
//unsigned int keyBlockLength = sizeof(keyString)
// 密钥编排方案
unsigned int * keySchedule(unsigned int keyString) {

    int keyBlockLen = KEYScheduleRound;
    unsigned int * keyArr = malloc(sizeof(unsigned int) * keyBlockLen);
    for (int i = 0; i < keyBlockLen; i++) {
        keyArr[keyBlockLen - i - 1] = keyString & 0xffff;
        keyString >>= 4;
    }
    return keyArr;
}

// P盒子
unsigned int permutationChange(unsigned int input) {    // 0b 0100 0101 1101 0001
    int pBox[16] = {1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16};
    unsigned int xorBox[16] = {0x8000, 0x4000, 0x2000, 0x1000, 0x800, 0x400, 0x200, 0x100, 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1};
    unsigned int result[16];
    unsigned int xorResult = 0x0000;
    for (int i = 0; i < 16; i++) {
        if ((i+1) - pBox[i] <= 0) {
            result[i] = (xorBox[i] & input) >> abs(pBox[i] - (i + 1));
        } else {
            result[i] = ((xorBox[i] & input) << abs(pBox[i] - (i + 1))) & 0xffff;
        }
        xorResult |= result[i];
    }
    return xorResult;
}

unsigned int permutationReverseChange(unsigned int input) {
    unsigned int final;
    final = permutationChange(input);
    return final;
}

unsigned int spn_decode(unsigned int y, unsigned long keyString) {
//    printf("y = %x", y);
//    printf("k = %lx\n", keyString);
    KEYScheduleRound = getKeyStringBlockLength(keyString) - 3;
//    printf("%d", KEYScheduleRound);
    int keyBlockLen = KEYScheduleRound;
    unsigned int * keyArr = malloc(sizeof(unsigned int) * keyBlockLen);
    memcpy(keyArr, keySchedule(keyString), sizeof(unsigned int) * keyBlockLen);

    unsigned int * wArr = malloc(sizeof(unsigned int) * keyBlockLen);
    unsigned int * vArr = malloc(sizeof(unsigned int) * keyBlockLen);
    unsigned int * uArr = malloc(sizeof(unsigned int) * keyBlockLen);

    // spn解密
    vArr[KEYScheduleRound - 1] = xorChange(y, keyArr[KEYScheduleRound - 1]);
//    printf("vArr[4] = %x\n", vArr[KEYScheduleRound - 1]);
//    printf("keyArr[4] = %x\n", keyArr[KEYScheduleRound - 1]);
    uArr[KEYScheduleRound - 1] = substitutionReverseChange(vArr[KEYScheduleRound - 1]);
    wArr[KEYScheduleRound - 2] = xorChange(keyArr[KEYScheduleRound - 1 - 1], uArr[KEYScheduleRound - 1]);
//    printf("u4 = %x\n", uArr[KEYScheduleRound - 1]);
//    printf("w3 = %x\n", wArr[KEYScheduleRound - 2]);
//    printf("k4 = %x\n", keyArr[3]);
    for (int r = KEYScheduleRound - 2; r > 0; r--) {
        vArr[r] = permutationReverseChange(wArr[r]);
        uArr[r] = substitutionReverseChange(vArr[r]);
        wArr[r-1] = xorChange(uArr[r], keyArr[r-1]);
//        printf("v%d = %x\n", r, vArr[r]);
//        printf("u%d = %x\n", r, uArr[r]);
//        printf("w%d = %x\n", r-1, wArr[r-1]);
//        printf("k%d = %x\n", r, keyArr[r-1]);
    }
//    printf("%x", wArr[0]);
    return wArr[0];
}


unsigned int spn_create(unsigned int x, unsigned long keyString) {
    KEYScheduleRound = getKeyStringBlockLength(keyString) - 3;
    // 0011 1010 1001 0100 1101 0110 0011 1111;
    // 密钥编排获得 KEYScheduleRound 轮的密钥
//    unsigned int keyString = 0b00111010100101001101011000111111;
    int keyBlockLen = KEYScheduleRound;
    unsigned int * keyArr = malloc(sizeof(unsigned int) * keyBlockLen);
    memcpy(keyArr, keySchedule(keyString), sizeof(unsigned int) * keyBlockLen);

    unsigned int * wArr = malloc(sizeof(unsigned int) * keyBlockLen);
    unsigned int * vArr = malloc(sizeof(unsigned int) * keyBlockLen);
    unsigned int * uArr = malloc(sizeof(unsigned int) * keyBlockLen);

    // SPN加密

    wArr[0] = x;
    //printf("w0: %x\n", wArr[0]);

    // 循环进行 KEYScheduleRound-2 轮
    for (int r = 1; r < KEYScheduleRound - 1; r++) {   // r => [1,3]
        //printf("k%d: %x\n", r, keyArr[r-1]);
        uArr[r] = xorChange(wArr[r-1], keyArr[r-1]);
        //printf("u%d: %x\n", r, uArr[r]);
        // S盒子
        vArr[r] = substitutionChange(uArr[r]);
        //printf("v%d: %x\n", r, vArr[r]);
        // P盒子
        wArr[r] = permutationChange(vArr[r]);
        //printf("w%d: %x\n", r, wArr[r]);
    }

    // 之后进行一次S盒子，一次白化
    // r = 4
    uArr[KEYScheduleRound - 1] = xorChange(wArr[KEYScheduleRound - 2], keyArr[KEYScheduleRound - 1 -1]);
    // S盒子
    vArr[KEYScheduleRound - 1] = substitutionChange(uArr[KEYScheduleRound - 1]);
    // 输出再做一次白化
    unsigned int y;
    y = xorChange(vArr[KEYScheduleRound - 1], keyArr[KEYScheduleRound - 1]);

    return y;
}



