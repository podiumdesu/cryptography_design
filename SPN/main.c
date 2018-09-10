#include <stdio.h>
#include <stdlib.h>
#include "spn_create.h"


int max = 1310720;    // 10M
unsigned long long k1=0x123ab25df686c124;
unsigned long long k2=0x973a5b6c7f7a654d;
unsigned long long x1=0x0000000000000000;
unsigned long long x2=0x0000000000000000;
unsigned long long iv1=0x3a94d63f12345678;
unsigned long long iv2=0x3a94d63f12345678;

int main (void) {
    int choice;

    int op = 1;
    char filename[]="cipherdataOld";

    unsigned long long * cipherdata;
    cipherdata = (unsigned long long *) malloc(sizeof(unsigned long long) * max);

    unsigned long save_spn_x_encryption[100];
    unsigned long save_spn_y_encryption[100];
    unsigned long long save_spn_k_encryption[100];
    unsigned long save_spn_x_decryption[100];
    unsigned long save_spn_y_decryption[100];
    unsigned long long save_spn_k_decryption[100];
    int save_spn_num = 0;
    int save_spn_num_decryption = 0;
//    x = 0x3333fdfdffffdada;
//    printf("输入明文为：%lx", x);
    unsigned long long keyString = 0b00111010100101001101011000111111;

    unsigned long input_x, input_y;

    char change_key_choice;

    while(op) {
//        system("clear");
        printf("\n");
        printf("                  密码学课程设计          \n");
        printf("-------------------------------------------------\n");
        printf("  1. SPN 加密明文                2. SPN 解密密文\n");
        printf("  3. SPN 线性分析                4. SPN 差分分析\n");
        printf("  5. 查看当前参数及历史记录      6. 生成 SPN 检测\n");
//        printf("  7. 增强 SPN 加密明文       8. 增强 SPN 解密密文\n");
//        printf("  9. 生成增强 SPN 随机检测\n");
        printf("  0. 退出\n");
        printf("-------------------------------------------------\n");
        printf("请选择你的操作[0~6]: ");
        scanf("%d", &op);
        switch (op) {
            case 1:
                printf("请输入明文 x （4个16进制数）：");
                scanf("%lx", &input_x);
                save_spn_x_encryption[save_spn_num] = input_x;
                unsigned int y = spn_create(input_x, keyString);
                save_spn_y_encryption[save_spn_num] = y;
                save_spn_k_encryption[save_spn_num] = keyString;
                save_spn_num++;
                printf("加密得密文 y ：%x\n", y);
                printf("请按回车键继续......\n");
                getchar();
                getchar();
                break;
            case 2:
                printf("请输入密文 y ：");
                scanf("%lx", &input_y);
                save_spn_x_decryption[save_spn_num_decryption] = input_y;
                unsigned int new = spn_decode(input_y, keyString);
                save_spn_y_decryption[save_spn_num_decryption] = new;
                save_spn_k_decryption[save_spn_num_decryption] = keyString;
                save_spn_num_decryption++;
                printf("解密得明文 x ：%x\n", new);
                printf("请按回车键继续......\n");
                getchar();
                getchar();

                break;

            case 3:
                printf("正确密钥应为 %llx\n", keyString);
                printf("正在对密钥进行线性分析中.......\n");
                spn_linear_analysis(keyString);
                printf("请按回车键继续......\n");
                getchar();
                getchar();
                break;
            case 4:
                printf("正确密钥应为 %llx\n", keyString);
                printf("正在对密钥进行差分分析中.......\n");
                spn_diff_analysis(keyString);
                printf("请按回车键继续......\n");
                getchar(); 
                getchar();
                break;
            case 5:
                printf("当前SPN基本参数如下所示：\n");
                printf("当前使用密钥为: %llx\n", keyString);
                printf("------- 历史加密记录 -------\n");
                if (save_spn_num > 0) {
                    printf("明文     密钥      密文\n");
                    for (int i = 0; i < save_spn_num; i++) {
                        printf("%lx   %llx    %lx\n", save_spn_x_encryption[i], save_spn_k_encryption[i], save_spn_y_encryption[i]);
                    }
                } else {
                    printf("暂无...\n");
                }
                printf("\n");
                printf("------- 历史解密记录 -------\n");
                if (save_spn_num_decryption > 0) {
                    printf("密文     密钥      明文\n");
                    for (int j = 0; j < save_spn_num_decryption; j++) {
                        printf("%lx   %llx    %lx\n", save_spn_x_decryption[j], save_spn_k_decryption[j], save_spn_y_decryption[j]);
                    }
                } else {
                    printf("暂无...\n");
                }
                printf("\n\n修改密钥？[y/n]  ");
                scanf(" %c", &change_key_choice);
                if (change_key_choice == 'y') {
                    printf("请重新输入密钥(30位)：");
                    scanf("%llx", &keyString);
                } else if (change_key_choice == 'n') {
//                    printf("当前使用密钥为: %llx\n", keyString);
                }
                printf("请按回车键继续......\n");
                getchar();
                getchar();
                break;
            case 6:
                printf("正在生成随机检测所需要的密文....\n");
                cipherdata[0] = spn_create(x1^iv1, k1);
                cipherdata[1] = spn_create(x2^iv2, k2);
                for (int k = 0; k < max / 2; k++) {
                    cipherdata[k*2] = spn_create(cipherdata[k*2-1]^x1, k1);
                    cipherdata[k*2+1] = spn_create(cipherdata[k*2]^x2, k2);
                }
                FILE *fp;
                fp = fopen(filename, "wb");
                for (int k = 0; k < max; k++) {
                    fwrite(&cipherdata[k], sizeof(unsigned long long), 1, fp);
                }
                fclose(fp);
                printf("随机检测所需要的密文生成成功！\n");
                break;
            case 0:
                printf("\n欢迎下次使用本系统\n");
                op = 0;
                break;
        }
    }
    return 0;
}




//    keyString = 0b00111010100101001101011000111111;
//    keyString = 0b0011101001010010111011110101111000111101;
//    keyString = 0b00111010100101001101011000100111;
