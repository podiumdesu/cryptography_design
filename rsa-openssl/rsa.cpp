
//
// Created by PetnaKanojo on 2018/8/23.
//

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "overall.h"
#include "rsaAlg.h"

int main() {
    int op = 1;
    BN_set_word(zero, 0);
    BN_set_word(one, 1);
    BN_set_word(two, 2);
    while (op) {
        printf("\n\n");
        printf("               RSA算法          \n");
        printf("---------------------------------------\n");
        printf("         1. RSA参数生成          \n");
        printf("         2. 中国剩余定理加解密        \n");
        printf("         3. 模重复平方算法加解密       \n");
        printf("         4. 蒙哥马利算法加解密         \n");
        printf("         0. 退出                 \n");
        printf("---------------------------------------\n");
        printf("请选择你的操作[0~4]:");
        scanf("%d", &op);
        switch (op) {
            case 1:
                RSADisplayPara();
                printf("按任意键继续...");
                getchar();
                getchar();
                break;
            case 2:
                chinaAlg();
                printf("按任意键继续...");
                getchar();
                getchar();
                break;
            case 3:
                modRepeatAlg();
                printf("按任意键继续...");
                getchar();
                getchar();
                break;
            case 4:
                montAlg();
                printf("按任意键继续...");
                getchar();
                getchar();
                break;
            case 0:
                break;
            default:
                printf("\n输入错误!\n");
                break;
        }
    }
    printf("欢迎下次继续使用本系统！\n");
    freeAllBigNum();    // 释放所有的大数
    return 0;
}

