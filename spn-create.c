//
// Created by PetnaKanojo on 2018/8/2.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "shiftFunc.h"
#include "myLib.h"

/*
 * 函数名：ROL           rotateRight
 * 输入：  (unsigned short unit, int nBit)
 * 输出：  unsigned short result
 * 示例：  *input:* 1010 1010 0001 0101, 6
 *       *output:* 1000 0101 0110 1010
 */


#define KEYScheduleRound 5


char * stringSplit(char * string, char *delim, int len) { // len左移的数量
    char result[100][5];
    if (len > 0) {
        int i = 0;
        char *temp = malloc(sizeof(char) * 5 * (len / 4));
        strcpy(temp, strtok(string, delim));
        strcat(temp, " ");
        for (int j = 1; j < (len / 4); j++) {
            strcpy(temp, strtok(NULL, delim));
            strcat(temp, " ");
        }
        char *p;
        while((p = strtok(NULL, delim))) {
            strcpy(result[i], p);
            strcat(result[i], " ");
            i++;
        }
        strcpy(result[i], temp);
    } else {
        int i = 0;
        strcpy(result[i], strtok(string, delim));
        strcat(result[i], " ");
        char *p;
        while((p = strtok(NULL, delim))) {
            i++;
            strcpy(result[i], p);
            strcat(result[i], " ");
        }
    }
    return result;
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
   }
}

unsigned int substitutionChange(unsigned int input) {   // 输入0b 0001 1100 0010 0011
    // 确定是16位的。
    unsigned int block1 = (0xf000 & input) >> 12;   // 0001 0000 0000 0000
    unsigned int block2 = (0x0f00 & input) >> 8;   // 0000 1100 0000 0000
    unsigned int block3 = (0x00f0 & input) >> 4;   // 0000 0000 0010 0000
    unsigned int block4 = (0x000f & input) >> 0;   // 0000 0000 0000 0011
//    printf("%d ", block1);
//    printf("%d ", block2);
//    printf("%d ", block3);
//    printf("%d ", block4);
    block1 = substitutionBox(block1) << 12;
    block2 = substitutionBox(block2) << 8;
    block3 = substitutionBox(block3) << 4;
    block4 = substitutionBox(block4) << 0;
    return block1 | block2 | block3 | block4;
}


unsigned int xorChange(unsigned int input, unsigned int key) {
    return input ^ key;
}


unsigned int * keySchedule(unsigned int keyString) {
    // 0011 1010 1001 0100 1101 0110 0011 1111;

    int keyBlockLen = KEYScheduleRound;
    unsigned int * keyArr = malloc(sizeof(unsigned int) * keyBlockLen);
    for (int i = 0; i < keyBlockLen; i++) {
        keyArr[keyBlockLen - i - 1] = keyString & 0xffff;
        printf("%x ", keyArr[keyBlockLen - i - 1]);
        keyString >>= 4;
    }
    return keyArr;
}

int permutationBox(int input) {

}

int getOneBlock(int num) {

}

int main (void) {
    // 0011 1010 1001 0100 1101 0110 0011 1111;

    // 密钥编排：
    unsigned int keyString = 0b00111010100101001101011000111111;
    int keyBlockLen = KEYScheduleRound;
    unsigned int * keyArr = malloc(sizeof(unsigned int) * keyBlockLen);
    keyArr = keySchedule(keyString);
    for (int i = 0; i < keyBlockLen; i++) {
        printf("\n\n%x", keyArr[i]);
    }

    // 输入加密文字
    int x = 0b0001110000100011;
    printf("hhhh%x\n", substitutionChange(a));
    unsigned short unit = 0xfefe;
//    printf("%x\n", getHighBitOne(4));
//    printf("%x\n", ROL(unit, 6));
//    bitPrintf(ROR(unit, 4));
//    bitPrintf(ROR(unit, 6));
    int k = 0x3A94D63f;






//    bitPrintf(k);
    unsigned short ddd;
    printf("%x", substitutionBox(10));
    ddd = ROL(k, 4);

    char s[100] = "0011 1010 1001 0100 1101 0110 0011 1111";;
    char *delim = " ";
    char *p;
    int res;
    char result[100][5];
    strcpy(result, stringSplit(s, delim, 4));
    printf("\n");
    printf("\n");
    printf("%sdone\n", *result);
    strcpy(result, stringSplit(result, delim, 4));
    printf("%sdone\n", *result);
    strcpy(result, stringSplit(result, delim, 0));
    printf("%sdone", *result);

    int test1 = 0x3; // 0011
    int test2 = 0xa; // 1010
    printf("%x", test1 | test2);


}


// x: 0010 0110 1011 0111
// k: 0011 1010 1001 0100 1101 0110 0011 1111

