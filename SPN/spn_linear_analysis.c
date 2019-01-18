//
// Created by PetnaKanojo on 2018/8/6.
//

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include "spn_create.h"

#define T 12000     // 测试明密文对数

unsigned int spn_linear_analysis (unsigned int initKeyString) {
    clock_t startClock, finish;
    startClock = clock();
    double duration;

    unsigned int X[T];
    unsigned int Y[T];
    unsigned int X_1[T];
    unsigned int Y_1[T];

    unsigned int bitX[16] = {0};
    unsigned int bitU[16] = {0};

    unsigned int X0 = 0x0B00;  //差分
//    printf("正确密钥应为：%x\n", initKeyString);

    unsigned int maxkey1, maxkey2;
    short count[16][16] = {0};
    for (int i = 0; i < T; i++) {
        srand(time(0) + rand());
        X[i] = rand() % 65535;
//        printf("x: %04x\n", X[i]);
        Y[i] = spn_create(X[i], initKeyString);
//        printf("y: %04x\n", Y[i]);
        X_1[i] = X[i] ^ X0;
        Y_1[i] = spn_create(X_1[i], initKeyString);
    }

    unsigned int y1, y3, y_1, y_2, y_3, y_4, v2, v4, y2, y4, u2, u4;
    unsigned int v_2, v_4, u_2, u_4;
    unsigned int u__2, u__4;
    unsigned int L1, L2;
    for (int i = 0; i < T; i++) {
        y1 = (Y[i] & 0xf000) >> 12;
        y2 = (Y[i] & 0x0f00) >> 8;
        y3 = (Y[i] & 0x00f0) >> 4;
        y4 = (Y[i] & 0x000f);
        y_1 = (Y_1[i] & 0xf000) >> 12;
        y_2 = (Y_1[i] & 0x0f00) >> 8;
        y_3 = (Y_1[i] & 0x00f0) >> 4;
        y_4 = (Y_1[i] & 0x000f);
        if ( (y1 == y_1) && (y3 == y_3)) {
            for (int L = 0; L < 0x00ff; L++) {
                L1 = (L & 0x00f0) >> 4;
                L2 = (L & 0x000f);
                v2 = L1 ^ y2;
                v4 = L2 ^ y4;
                u2 = substitutionReverseChange(v2);
                u4 = substitutionReverseChange(v4);

                v_2 = L1 ^ y_2;
                v_4 = L2 ^ y_4;
                u_2 = substitutionReverseChange(v_2);
                u_4 = substitutionReverseChange(v_4);

                u__2 = u2 ^ u_2;
                u__4 = u4 ^ u_4;

                if ( (u__2 == 0x6) && (u__4) == 0x6) {
                    count[L1][L2]++;
                }
            }
        }
    }

    int max = -1;
    for (int L = 0; L < 0x00ff; L++) {
        L1 = (L & 0x00f0) >> 4;
        L2 = (L & 0x000f);
        if (count[L1][L2] > max) {
            max = count[L1][L2];
            maxkey1 = L1;
            maxkey2 = L2;
        }
    }
    printf("maxkey1 : %x, maxkey2: %x\n", maxkey1, maxkey2);

    unsigned int Y_test;
    int flag1 , flag2 = 1;
    unsigned int maxkey;
    clock_t start, end;
    start = clock();
    for (unsigned int key = 0; key <= 0xffff && flag2 == 1; key++) {
        for (unsigned int key1 = 0; key1 <= 0xf && flag2 == 1; key1++) {
            for (unsigned int key2 = 0; key2 <= 0xf && flag2 == 1; key2++) {
                maxkey = (key << 16) | (key1 << 12) | (maxkey1 << 8) | (key2 << 4) | maxkey2;
                int i = 0;
                flag1 = 1;
                while (i <= 20 && flag1 == 1) {
//                    printf("maxkey = %x\n", maxkey);
                    Y_test = spn_create(X[i], maxkey);
                    if (Y_test != Y[i]) {
//                        printf("%x, %x", Y_test, Y[i]);
                        flag1 = 0;
                    } else if ((Y_test == Y[i]) && (i == 20)) {
                        printf("线性分析后得：SPN密钥为：%x\n", maxkey);
                        flag2 = 0;
                    }
                    i++;
                }
            }
        }
    }
    end = clock();
    finish = clock();
    duration = (double)(finish - startClock) / CLOCKS_PER_SEC;
    printf( "%f seconds\n", duration );
    return maxkey;
};