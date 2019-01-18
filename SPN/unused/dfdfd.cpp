#include <stdio.h>
#include <stdlib.h>
#define Nr 16
int  S[16][16]={
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
			{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
			{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
			{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
			{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
			{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
			{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
			{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
			{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
			{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
			{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
			{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
			{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
			{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
			{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
			{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
        };                          //AES����
int Pbox[16]={0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15};      //vÿһλ�û����λ��,���û�����
int  S_inverse[16][16]={0};          //S���ӵ���
long long key[Nr+1]={0};
long long w=0;
long long u=0;
long long v=0;
int max = 1310720;//10M
unsigned long long k1=0x123ab25df686c124;
unsigned long long k2=0x973a5b6c7f7a654d;
unsigned long long x1=0x0000000000000000;
unsigned long long x2=0x0000000000000000;
unsigned long long iv1=0x3a94d63f12345678;
unsigned long long iv2=0x3a94d63f12345678;
/**********************SPN��ǿ����*************************/
long long s_arrange (long long u,int S[16][16]);//�ӡ�����S�������
long long p_arrange (long long u);              //����P�����û�
long long p_spn(int  u);                        //ԭʼspn��ʮ�������û�������p_arrange��
long long spn_encryption(long long x,long long K);
/**********************SPN��ǿ����*************************/

/**********************SPN��ǿ����*************************/
void sbox_inverse(int S[16][16],int S_inverse[16][16]);//����ʱ���õ�S�������
long long p_inverse (long long u);                     //����P�������û�
long long spn_dncryption(long long y,long long K);
/**********************SPN��ǿ����*************************/

/************************��Կ����**************************/
unsigned long long KL_LShift(unsigned long long KL,int t); //��Կ����ʱKLѭ������
unsigned long long KR_LShift(unsigned long long KR,int t); //��Կ����ʱKRѭ������
void k_arrange (long long K,long long key[Nr+1]);          //��Կ���ŷ���

/************************��Կ����**************************/

/************************����ת��**************************/
long long bit_to_num1(int  bit[64]);        //64λ2����ת��Ϊ10���ƣ���Կ����ʹ��
void num_to_bit1(int  bit[64],long long u); //10����ת��Ϊ64λ2���ƣ���Կ����ʹ��
int  bit_to_num(int  bit[16]);              //10����ת��Ϊ16λ2����
void num_to_bit(int  bit[16],int u);        //16λ2����ת��Ϊ10����
long long char_to_hex(char x_128[32],int m);//�ַ���ת��Ϊ16��������
/************************����ת��**************************/
int main()
{
    int op=1,i;
    char x_128[32],k_128[32],y_128[32];
    char c;
    char filename[]="cipherdata";
    long long X1,Y1,K1,X2,Y2,K2,K,Y,X;    //64����
    long long a,b,p,q;
    do{
        printf("\n\n");
        printf("            SPN�ļӽ�����ǿ      \n\n");
        printf("*****************���Բ˵�********************\n\n");
        printf("***         1.ʵ��SPN�ļ���               ***\n\n");
        printf("***         2.ʵ��SPN�Ľ���               ***\n\n");
        printf("***         3.��ǿ��SPN�ĵ�������       ***\n\n");
        printf("***         0.�˳�                        ***\n\n");
        printf("*********************************************\n\n");
        printf("��ѡ����Ĳ���[0~3]:");
        scanf("%d",&op);
	    getchar();
	    switch(op){
             case 1:
                 printf("����������ܵ����ģ�32��16����������\n");
                 for(i=0;i<32;i++){
                    c=getchar();
                    x_128[i]=c;
                 }
                 getchar();
                 X1=char_to_hex(x_128,0);
                 X2=char_to_hex(x_128,16);              //���������128����
                 printf("��������Կ��32��16����������\n");
                 for(i=0;i<32;i++){
                    c=getchar();
                    k_128[i]=c;
                 }
                 K1=char_to_hex(k_128,0);
                 K2=char_to_hex(k_128,16);
                 a=K1&0xffffffff00000000; b=K1&0x00000000ffffffff;
                 p=K2&0xffffffff00000000; q=K2&0x00000000ffffffff;
                 K1=0;K2=0;
                 K1=p|b;
                 K2=a|q;                       //128λ��Կ����
                 Y1=spn_encryption(X1,K1);
                 Y2=spn_encryption(X2,K2);
                 printf("������ܺ�����ģ�32��16����������\n");
                 printf("%llx%llx\n",Y1,Y2);
		         break;
             case 2:
                 printf("����������ܵ����ģ�32��16����������\n");
                 for(i=0;i<32;i++){
                    c=getchar();
                    y_128[i]=c;
                 }
                 getchar();
                 Y1=char_to_hex(y_128,0);
                 Y2=char_to_hex(y_128,16);              //���������128����
                 printf("��������Կ��32��16����������\n");
                 for(i=0;i<32;i++){
                    c=getchar();
                    k_128[i]=c;
                 }
                 K1=char_to_hex(k_128,0);
                 K2=char_to_hex(k_128,16);
                 a=K1&0xffffffff00000000; b=K1&0x00000000ffffffff;
                 p=K2&0xffffffff00000000; q=K2&0x00000000ffffffff;
                 K1=0;K2=0;
                 K1=p|b;
                 K2=a|q;                       //128λ��Կ����
                 X1=spn_dncryption(Y1,K1);
                 X2=spn_dncryption(Y2,K2);
                 printf("������ܺ�����ģ�32��16����������\n");
                 printf("%llx%llx\n",X1,X2);
		         break;
             case 3:
                unsigned long long * cipherdata;
                cipherdata=(unsigned long long*)malloc(sizeof(unsigned long long)*max);
                cipherdata[0]=spn_encryption(x1^iv1,k1);
                cipherdata[1]=spn_encryption(x2^iv2,k2);
                for(i=1;i<max/2;i++){
                    cipherdata[i*2]=spn_encryption(cipherdata[i*2-1]^x1,k1);
                    cipherdata[i*2+1]=spn_encryption(cipherdata[i*2]^x2,k2);
                }                                                 //��������
                FILE *fp;
                fp=fopen(filename,"wb");
                for(i=0;i<max;i++)
                fwrite(&cipherdata[i],sizeof(unsigned long long),1,fp);
                fclose(fp);
                printf("����������Ҫ���������ɳɹ���");
                break;
             case 0:
                printf("\n��ӭ�´η���\n");
                break;
             default:
                printf("\n�������!\n");
                break;
	    }
    printf("\n");
    system("pause");
    system("cls");
    }while(op);
    return 0;
}

/************************��Կ����**************************/
/*��Կ����ʱKLѭ������*/
unsigned long long KL_LShift(unsigned long long KL,int t){
    unsigned long long k;
    k=KL>>(32-t);
    KL=(KL<<t)|k;
    return KL;
}
/*��Կ����ʱKLѭ������*/
unsigned long long KR_LShift(unsigned long long KR,int t){
    unsigned long long k;
    k=KR>>(32-t);
    KR=(KR<<t)|k;
    KR=KR&0x00000000ffffffff;
    return KR;
}
/*����DES����Կ����*/
void k_arrange (long long K,long long key[Nr+1]){
    int i,j;
    int  P_K[64]={57,49,41,33,25,17,9,8,1,58,50,42,34,26,18,16,
                  10,2,59,51,43,35,27,24,19,11,3,60,52,44,36,32,
                  63,55,47,39,31,23,15,40,7,62,54,46,38,30,22,48,
                  14,6,61,53,45,37,29,56,21,13,5,28,20,12,4,64};
    unsigned long long KL,KR;
    int  P_temp[64]={0};
    int  p_bit[64]={0};
    num_to_bit1(P_temp,K);         //��������Կ���64��������
    for(i=0;i<64;i++)
        p_bit[i]=P_temp[P_K[i]-1]; //�û�
    K=bit_to_num1(p_bit);          //���û����64λ�����ƴ���Ϊʮ����K,��ʼ�û�
    KL=K&0xffffffff00000000;
    KR=K&0x00000000ffffffff;       //��K��Ϊ����������
    KL=KL_LShift(KL,1);
    KR=KR_LShift(KR,1);            //�ֱ�ѭ������һλ
    key[0]=KL|KR;                  //��һ����Կ
    KL=KL_LShift(KL,1);
    KR=KR_LShift(KR,1);
    key[1]=KL|KR;
    for(i=2;i<=8;i++){
        KL=KL_LShift(KL,1);
        KR=KR_LShift(KR,1);
        key[i]=KL|KR;
    }
    for(i=9;i<=15;i++){
        KL=KL_LShift(KL,2);
        KR=KR_LShift(KR,2);
        key[i]=KL|KR;
    }
    key[16]=K;                   //���һ��
}
/************************��Կ����**************************/

/************************����ת��**************************/
/*16����2���ƴ�ת��Ϊ10������*/
int  bit_to_num(int  bit[16]){
    int  num=0;
    int i;
    for(i=0;i<16;i++)
        num=num*2+bit[i];
    return num;
}
/*16���س�10������ת��Ϊ16λ2���ƴ�*/
void num_to_bit(int  bit[16],int  u){
    int i,con=u;
    for(i=0;i<16;i++)
        bit[i]=0;
    for(i=15;i>=0;i--){
        bit[i]=con%2;
        con=con/2;
    }
}
/*64����2���ƴ�ת��Ϊ10������*/
long long bit_to_num1(int bit[64]){
    long long num=0;
     int i;
    for(i=0;i<64;i++)
        num=num*2+bit[i];
    return num;
}
/*64���س�10������ת��Ϊ64λ2���ƴ�*/
void num_to_bit1(int  bit[64],long long u){
    int i;
    for(i=0;i<64;i++)
        bit[i]=0;
    long long  con;
    con=u;
    for(i=63;i>=0;i--){
        bit[i]=con%2;
        con=con/2;
    }
}
/*�ַ���ת��Ϊ16λ16����*/
long long char_to_hex(char x_128[32],int m){
    int i,temp[32];
    long long x=0;
    for(i=0;i<16;i++){
        if(x_128[i+m]>='0'&&x_128[i+m]<='9')
            temp[i]=x_128[i+m]-'0';
        else temp[i]=x_128[i+m]-87;
        x=temp[i]+x*16;
    }
    return x;
}
/************************����ת��**************************/

/**********************SPN��ǿ����*************************/
/*64�������ļӡ�����s��(�棩����*/
long long s_arrange (long long u,int S[16][16]){   //����ʱ��S��������S_inverse
    int i;
    long long v=0;
    long long t0[8]={0xff00000000000000,0x00ff000000000000,0x0000ff0000000000,0x000000ff00000000,
    0x00000000ff000000,0x0000000000ff0000,0x000000000000ff00,0x00000000000000ff};//һ��64λ���ģ���Ϊ8��
    long long t[8];
    int  low,high,swap;
    for(i=0;i<8;i++)
        t[i]=(u & t0[i])>>(56-i*8);       //��u�е�ÿ16λ�����t[i]�У���λ��������Ҫ����56λ���Դ�����
    for(i=0;i<8;i++){
        low=(t[i] & 0x0f);
        high=(t[i] & 0xf0)>>4;
        swap=S[high][low];                //��t[i]������16����������ΪS��������н����滻
        t[i]=(long )swap;
        t[i]=t[i] << (56-i*8);            //��t[i]���ӳ�64����
        v=v|t[i];                         //������ӣ�t[i]ÿһ������λ�ò�ͬ����򼴿�����
    }
    return v;
}
/*����p�û�*/
long long p_arrange(long long v){    //p���û�����64λ���ݷ�Ϊ8��
    unsigned long long b[4];
    unsigned long long t[8];                  //��v��Ϊ8�飬ÿһ�����ֵ���������t��
    t[0]=0xff00000000000000 & v; t[4]=0x00000000ff000000 & v;
    t[1]=0x00ff000000000000 & v; t[5]=0x0000000000ff0000 & v;
    t[2]=0x0000ff0000000000 & v; t[6]=0x000000000000ff00 & v;
    t[3]=0x000000ff00000000 & v; t[7]=0x00000000000000ff & v;
	v=(t[0]>>56)|(t[1]>>24)|(t[2]>>8)|(t[3]<<24)|(t[4]>>16)|(t[5])|(t[6]<<32)|(t[7]<<48);
                                                        //��8�����ݰ���p�й��򽻻�λ�ã��û�,v�������
	b[0]=(0x000000000000ffff&v);
	b[1]=(0x00000000ffff0000&v)>>16;
	b[2]=(0x0000ffff00000000&v)>>32;
	b[3]=(0xffff000000000000&v)>>48;
	v=(p_spn(b[3])<<48)|(p_spn(b[2])<<32)|(p_spn(b[1])<<16)|p_spn(b[0]);
                                                        //��8���û���ķ�Ϊ4�飬һ��16���أ�ÿһ�����ԭʼspn���û�
	return v;
}
/*ԭʼP���û�*/
long long p_spn(int u){
    int i;
    int P_temp[16]={0};
    int p_bit[16]={0};
    num_to_bit(P_temp,u);         //u���16λ������
    for(i=0;i<16;i++)
        p_bit[i]=P_temp[Pbox[i]]; //16λ�û�������Pbox�Ĺ���
    u=bit_to_num(p_bit);          //�û����16λ�����Ʊ�Ϊu
    u=(long )u;
    return u;
}
/*spn��ǿ����*/
long long spn_encryption(long long x,long long K){
    long long y;
    int i;
    k_arrange(K,key);      //��Կ����
    w=x;
    for(i=0;i<Nr-1;i++){   //ǰNr-1��
        u=key[i]^w;        //�׻�
        v=s_arrange(u,S);  //����
        w=p_arrange(v);    //�û�
    }
        u=key[Nr-1]^w;
        v=s_arrange(u,S);
        y=key[Nr]^v;       //���һ����򣬲��û�
        return y;
}
/**********************SPN��ǿ����*************************/

/**********************SPN��ǿ����*************************/
/*����ʹ��s�е���*/
void sbox_inverse(int S[16][16],int S_inverse[16][16]){
    int  i,j,temp,th,tl;
    for(i=0;i<16;i++)
        for(j=0;j<16;j++){
            temp=S[i][j];
            th=(temp & 0xf0)>>4;    //thΪ����λ
            tl=temp & 0x0f;         //tlΪ����λ
            temp=(i<<4)|j;          //i��Ϊ����λ��j��Ϊ����λ����Ϊs���Ԫ��
            S_inverse[th][tl]=temp; //th��tlΪtemp��λ��
        }       //���ܴ���ʱ����u�����ݱ��s����Ȼ����s�����ݴ���������ʱ��s���б��s_inverse���ݣ�s�е����ݱ�Ϊ����
}
/*64bit���Ľ���p�����û�*/
long long p_inverse(long long u){  //p�����û�����64λ���ݷ�Ϊ8��
    unsigned long long b[4];
    unsigned long long t[8];
    b[0]=(0x000000000000ffff&u);
	b[1]=(0x00000000ffff0000&u)>>16;
	b[2]=(0x0000ffff00000000&u)>>32;
	b[3]=(0xffff000000000000&u)>>48;
	u=(p_spn(b[3])<<48)|(p_spn(b[2])<<32)|(p_spn(b[1])<<16)|p_spn(b[0]);
                                    //��8���û���ķ�Ϊ4�飬һ��16���أ�ÿһ�����ԭʼspn�����û������û����û���ͬ
    t[0]=0xff00000000000000 & u; t[4]=0x00000000ff000000 & u;
    t[1]=0x00ff000000000000 & u; t[5]=0x0000000000ff0000 & u;
    t[2]=0x0000ff0000000000 & u; t[6]=0x000000000000ff00 & u;
    t[3]=0x000000ff00000000 & u; t[7]=0x00000000000000ff & u;
	u=(t[0]>>24)|(t[1]>>48)|(t[2]>>32)|(t[3]<<8)|(t[4]<<24)|(t[5])|(t[6]<<16)|(t[7]<<56);
                                  //��8�����ݰ���p�й��򽻻�λ�ã����û�
	return u;
}
/*spn��ǿ����*/
long long spn_dncryption(long long y,long long K){
    long long x;
    int i;
    k_arrange(K,key);
    sbox_inverse(S,S_inverse);//�����
    v=key[16]^y;              //��Կ���
    u=s_arrange(v,S_inverse); //�����
    w=key[15]^u;              //�׻�
    for(i=0;i<Nr-1;i++){
        v=p_inverse(w);       //���û�
        u=s_arrange(v,S_inverse);
        w=key[Nr-i-2]^u;
    }
    x=w;
        return x;
}
/**********************SPN��ǿ����*************************/
