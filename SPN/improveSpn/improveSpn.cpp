//
// Created by PetnaKanojo on 2018/9/1.
//

#include "improveSpn.h"
#include "overall.h"

#define Nr 16

/******************密钥编排方案**************/
unsigned long long KEY_L(unsigned long long KL, int t) {
    unsigned long long k;
    k = KL >> (32 - t);
    KL = (KL << t) | k;
    return KL;
}

unsigned long long KEY_R(unsigned long long KR, int t) {
    unsigned long long k;
    k = KR >> (32 - t);
    KR = (KR << t) | k;
    KR = KR & 0x00000000ffffffff;
    return KR;
}

/* DES*/
void KEY_Arr(long long K, long long key[Nr + 1]) {
    int i, j;
    int P_K[64] = {57, 49, 41, 33, 25, 17, 9, 8, 1, 58, 50, 42, 34, 26, 18, 16,
                   10, 2, 59, 51, 43, 35, 27, 24, 19, 11, 3, 60, 52, 44, 36, 32,
                   63, 55, 47, 39, 31, 23, 15, 40, 7, 62, 54, 46, 38, 30, 22, 48,
                   14, 6, 61, 53, 45, 37, 29, 56, 21, 13, 5, 28, 20, 12, 4, 64};
    unsigned long long KL, KR;
    int P_temp[64] = {0};
    int p_bit[64] = {0};
    numTo64Bit(P_temp, K);       // 数字密钥变为进制
    for (i = 0; i < 64; i++) {
        p_bit[i] = P_temp[P_K[i] - 1]; //置换
    }
    K = bit64ToNum(p_bit);          // 64位二进制 -> 十进制
    KL = K & 0xffffffff00000000;
    KR = K & 0x00000000ffffffff;
    KL = KEY_L(KL, 1);
    KR = KEY_R(KR, 1);
    key[0] = KL | KR;
    KL = KEY_L(KL, 1);
    KR = KEY_R(KR, 1);
    key[1] = KL | KR;
    for (i = 2; i <= 8; i++) {
        KL = KEY_L(KL, 1);
        KR = KEY_R(KR, 1);
        key[i] = KL | KR;
    }
    for (i = 9; i <= 15; i++) {
        KL = KEY_L(KL, 2);
        KR = KEY_R(KR, 2);
        key[i] = KL | KR;
    }
    key[16] = K;
}
/******************密钥编排方案**************/

/***************进制转换********************/
int bit16ToNum(int bit[16]) {
    int num = 0;
    int i;
    for (i = 0; i < 16; i++)
        num = num * 2 + bit[i];
    return num;
}


void numTo16Bit(int bit[16], int u) {
    int i, con = u;
    for (i = 0; i < 16; i++)
        bit[i] = 0;
    for (i = 15; i >= 0; i--) {
        bit[i] = con % 2;
        con = con / 2;
    }
}

long long bit64ToNum(int bit[64]) {
    long long num = 0;
    int i;
    for (i = 0; i < 64; i++)
        num = num * 2 + bit[i];
    return num;
}

void numTo64Bit(int bit[64], long long u) {
    int i;
    for (i = 0; i < 64; i++)
        bit[i] = 0;
    long long con;
    con = u;
    for (i = 63; i >= 0; i--) {
        bit[i] = con % 2;
        con = con / 2;
    }
}

long long charToHex(char x_128[32], int m) {
    int i, temp[32];
    long long x = 0;
    for (i = 0; i < 16; i++) {
        if (x_128[i + m] >= '0' && x_128[i + m] <= '9')
            temp[i] = x_128[i + m] - '0';
        else temp[i] = x_128[i + m] - 87;
        x = temp[i] + x * 16;
    }
    return x;
}
/*****************进制转换********************/

/*****************SPN加密********************/

long long substitutionChange(long long u, int S[16][16]) {   // 将 P 盒 传入
    int i;
    long long v = 0;
    long long t0[8] = {0xff00000000000000,
                       0x00ff000000000000,
                       0x0000ff0000000000,
                       0x000000ff00000000,
                       0x00000000ff000000,
                       0x0000000000ff0000,
                       0x000000000000ff00,
                       0x00000000000000ff};   // 用于异或
    long long t[8];
    int low, high, swap;
    for (i = 0; i < 8; i++) {
        t[i] = (u & t0[i]) >> (56 - i * 8);
    }
    for (i = 0; i < 8; i++) {
        low = (t[i] & 0x0f);
        high = (t[i] & 0xf0) >> 4;
        swap = S[high][low];
        t[i] = (long) swap;
        t[i] = t[i] << (56 - i * 8);
        v = v | t[i];           // 连接
    }
    return v;
}

long long permutationChange(long long v) {
    unsigned long long b[4];
    unsigned long long t[8];                  //分为8组
    t[0] = 0xff00000000000000 & v;
    t[4] = 0x00000000ff000000 & v;
    t[1] = 0x00ff000000000000 & v;
    t[5] = 0x0000000000ff0000 & v;
    t[2] = 0x0000ff0000000000 & v;
    t[6] = 0x000000000000ff00 & v;
    t[3] = 0x000000ff00000000 & v;
    t[7] = 0x00000000000000ff & v;
    v = (t[0] >> 56) | (t[1] >> 24) | (t[2] >> 8) | (t[3] << 24) | (t[4] >> 16) | (t[5]) | (t[6] << 32) | (t[7] << 48);
    // 交换位置，异或连接
    b[0] = (0x000000000000ffff & v);
    b[1] = (0x00000000ffff0000 & v) >> 16;
    b[2] = (0x0000ffff00000000 & v) >> 32;
    b[3] = (0xffff000000000000 & v) >> 48;
    v = (previousPChange(b[3]) << 48) | (previousPChange(b[2]) << 32) | (previousPChange(b[1]) << 16) | previousPChange(b[0]);   // 再进行一次置换
    return v;
}


long long previousPChange(int u) {    // 原始p置换
    int i;
    int P_temp[16] = {0};
    int p_bit[16] = {0};
    numTo16Bit(P_temp, u);
    for (i = 0; i < 16; i++) {
        p_bit[i] = P_temp[Pbox[i]];    // 置换
    }
    u = bit16ToNum(p_bit);
    u = (long) u;
    return u;
}

long long spn_encode(long long x, long long K) {
    long long y;
    int i;
    KEY_Arr(K, key);      // arrange the key
    w = x;
    for (i = 0; i < Nr - 1; i++) {   // 一共 Nr - 1 轮
        u = key[i] ^ w;     // 白化
        v = substitutionChange(u, S);   // 代换
        w = permutationChange(v);    // 置换
    }
    u = key[Nr - 1] ^ w;
    v = substitutionChange(u, S);
    y = key[Nr] ^ v;       //最后一轮异或
    return y;
}
/*****************SPN加密********************/

/*****************SPN解密********************/
void substitutionReverseChange(int S[16][16], int S_inverse[16][16]) {
    int i, j, temp, th, tl;
    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++) {
            temp = S[i][j];
            th = (temp & 0xf0) >> 4;   // 高四位
            tl = temp & 0x0f;
            temp = (i << 4) | j;
            S_inverse[th][tl] = temp;    // 获得内容的逆代换
        }
}

long long permutationReverseChange(long long u) {  // 分为8组进行逆置换
    unsigned long long b[4];
    unsigned long long t[8];
    b[0] = (0x000000000000ffff & u);
    b[1] = (0x00000000ffff0000 & u) >> 16;
    b[2] = (0x0000ffff00000000 & u) >> 32;
    b[3] = (0xffff000000000000 & u) >> 48;
    // 置换后分为4组，1组16bit，每组进行原始Spn的置换
    u = (previousPChange(b[3]) << 48) | (previousPChange(b[2]) << 32) | (previousPChange(b[1]) << 16) | previousPChange(b[0]);
    t[0] = 0xff00000000000000 & u;
    t[4] = 0x00000000ff000000 & u;
    t[1] = 0x00ff000000000000 & u;
    t[5] = 0x0000000000ff0000 & u;
    t[2] = 0x0000ff0000000000 & u;
    t[6] = 0x000000000000ff00 & u;
    t[3] = 0x000000ff00000000 & u;
    t[7] = 0x00000000000000ff & u;
    u = (t[0] >> 24) | (t[1] >> 48) | (t[2] >> 32) | (t[3] << 8) | (t[4] << 24) | (t[5]) | (t[6] << 16) | (t[7] << 56);
    return u;
}

long long spn_decode(long long y, long long K) {
    long long x;
    int i;
    KEY_Arr(K, key);
    substitutionReverseChange(S, S_inverse);
    v = key[16] ^ y;
    u = substitutionChange(v, S_inverse);
    w = key[15] ^ u;
    for (i = 0; i < Nr - 1; i++) {
        v = permutationReverseChange(w);
        u = substitutionChange(v, S_inverse);
        w = key[Nr - i - 2] ^ u;
    }
    x = w;
    return x;
}
/*****************SPN解密********************/
