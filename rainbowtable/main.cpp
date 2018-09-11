//
// Created by PetnaKanojo on 2018/9/10.
//

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "outerLib.h"
#include <math.h>
#include "myLib.h"


int main(void) {


    int n, s;
    n = 24, s = 22;

    int op = 1;
    while (op) {
        printf("\n\n");
        printf("               HASH              \n");
        printf("-------------------------------------\n");
        printf("            1.生成HASH值             \n");
        printf("            2.生成彩虹表            \n");
        printf("            3.解密HASH值             \n");
        printf("            0.退出                   \n");
        printf("-------------------------------------\n");
        printf("请选择你的操作[0~3]:");
        scanf("%d", &op);
//        getchar();
        int i;
        switch (op) {
            case 1: {
                unsigned char finalHash[16];
                unsigned char finalKey[16];
                printf("请输入原文：");
                scanf("%x", &i);
                printf("HASH值为：\n");
                assign(finalKey, i);
                sha1hash(finalKey, finalHash);
                printf("0x");
                printhex(finalHash);
                printf("按任意键继续...\n");
                getchar();
                getchar();
                break;
            }
            case 2: {
                printf("正在生成彩虹表...请稍后\n");
                FILE *rainbow = fopen("rainbow", "wb");
                if (rainbow == NULL) {
                    fputs("File error", stderr);
                    exit(1);
                }
                gentable(n, s, rainbow);
                fclose(rainbow);
                printf("彩虹表生成完成！\n");
                printf("按任意键继续...\n");
                getchar();
                getchar();
                break;
            }

            case 3: {
                unsigned char hash[16];
                char *input;
                input = (char *) malloc(sizeof(char) * 30);
                printf("\n请输入解密密文：");
                scanf("%s", input);
                int x;
                for (x = 0; x < 16; x++) {
                    char byte[2] = {input[2 * (x + 1)], input[2 * (x + 1) + 1]};
                    hash[x] = strtol(byte, NULL, 16);
                }

                FILE *read = fopen("rainbow", "rb");
                if (read == NULL) {
                    fputs("File error", stderr);
                    exit(1);
                }

                long lsize;
                fseek(read, 0, SEEK_END);
                lsize = ftell(read);
                rewind(read);
                //printf("%lu \n", lsize);
                unsigned long rows = lsize / 20;
                int y;
                unsigned char (*table)[2][16];
                table = (unsigned char (*)[2][16]) malloc(sizeof(unsigned char) * rows * 32);

                int j;
                for (j = 0; j < rows; j++) {
                    unsigned char temp[4];
                    fread(temp, sizeof(unsigned char), 4, read);
                    pad(temp, table[j][0]);
                    fread(table[j][1], sizeof(unsigned char), 16, read);
                }
                fclose(read);
                crack(n, s, rows, table, hash);
                free(table);
                printf("按任意键继续...\n");
                getchar();
                getchar();
                break;
            }
            case 0: {
                printf("\n欢迎下次继续使用\n");
                break;
            }
            default: {
                printf("\n输入错误！!\n");
                break;
            }
        }
    }
}

