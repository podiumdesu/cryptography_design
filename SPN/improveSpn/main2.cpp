#include <stdio.h>
#include <stdlib.h>
#include "overall.h"
#include "improveSpn.h"

#define Nr 16   // 设定轮次

int main()
{
    int op=1,i;
    char x_128[32],k_128[32],y_128[32];
    char c;
    char filename[]="cipherdata";
    long long X1,Y1,K1,X2,Y2,K2,K,Y,X;    //64bit
    long long a,b,p,q;
    do{
        printf("\n\n");
        printf("            密码学课程设计      \n");
        printf("---------------------------------------\n");
        printf("         1. SPN加密               \n");
        printf("         2. SPN解密              \n");
        printf("         3. 增强的SPN的随机检测       \n");
        printf("         0. 退出                     \n");
        printf("---------------------------------------\n");
        printf("请选择你的操作[0~3]:");
        scanf("%d",&op);
        getchar();
        switch(op){
            case 1:
                printf("请输入待加密的明文（32 * 4位）：\n");
                for(i=0;i<32;i++){
                    c=getchar();
                    x_128[i]=c;
                }
                getchar();
                X1=charToHex(x_128,0);
                X2=charToHex(x_128,16);              //处理输入的128bit
                printf("请输入密钥（32 * 4位）：\n");
                for(i=0;i<32;i++){
                    c=getchar();
                    k_128[i]=c;
                }
                K1=charToHex(k_128,0);
                K2=charToHex(k_128,16);
                a=K1&0xffffffff00000000; b=K1&0x00000000ffffffff;
                p=K2&0xffffffff00000000; q=K2&0x00000000ffffffff;
                K1=0;K2=0;
                K1=p|b;
                K2=a|q;                       //128位密钥处理
                Y1=spn_encode(X1,K1);
                Y2=spn_encode(X2,K2);
                printf("加密后的密文（32 * 4位）\n");
                printf("%llx%llx\n",Y1,Y2);
                printf("请按任意键继续...");
                getchar();
                getchar();
                break;
            case 2:
                printf("请输入待解密的密文（32 * 4位）\n");
                for(i=0;i<32;i++){
                    c=getchar();
                    y_128[i]=c;
                }
                getchar();
                Y1=charToHex(y_128,0);
                Y2=charToHex(y_128,16);              //处理输入的128bit
                printf("请输入密钥（32 * 4位）\n");
                for(i=0;i<32;i++){
                    c=getchar();
                    k_128[i]=c;
                }
                K1=charToHex(k_128,0);
                K2=charToHex(k_128,16);
                a=K1&0xffffffff00000000; b=K1&0x00000000ffffffff;
                p=K2&0xffffffff00000000; q=K2&0x00000000ffffffff;
                K1=0;K2=0;
                K1=p|b;
                K2=a|q;                       //128位密钥处理
                X1=spn_decode(Y1,K1);
                X2=spn_decode(Y2,K2);
                printf("输出解密后的明文（32个16进制数）\n");
                printf("%llx%llx\n",X1,X2);
                printf("请按任意键继续...");
                getchar();
                getchar();
                break;
            case 3:
                printf("正在生成随机检测所需要的密文...\n");
                unsigned long long * cipherdata;
                cipherdata=(unsigned long long*)malloc(sizeof(unsigned long long)*max);
                cipherdata[0]=spn_encode(x1^iv1,k1);
                cipherdata[1]=spn_encode(x2^iv2,k2);
                for(i=1;i<max/2;i++){
                    cipherdata[i*2]=spn_encode(cipherdata[i*2-1]^x1,k1);
                    cipherdata[i*2+1]=spn_encode(cipherdata[i*2]^x2,k2);
                }                                                 //生成密文
                FILE *fp;
                fp=fopen(filename,"wb");
                for(i=0;i<max;i++)
                    fwrite(&cipherdata[i],sizeof(unsigned long long),1,fp);
                fclose(fp);
                printf("随机检测所需要的密文生成成功！\n");
                printf("请按任意键继续...");
                getchar();
                getchar();
                break;
            case 0:
                printf("\n欢迎下次使用本系统\n");
                break;
            default:
                printf("\n输入错误\n");
                printf("请按任意键继续...");
                getchar();
                getchar();
                break;
        }
        printf("\n");
    }while(op);
    return 0;
}

