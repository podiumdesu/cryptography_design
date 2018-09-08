//
// Created by PetnaKanojo on 2018/9/8.
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

/*64±»Ãÿ≥§10Ω¯÷∆ ˝◊™ªØŒ™64Œª2Ω¯÷∆¥Æ*/
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

/*◊÷∑˚¥Æ◊™ªªŒ™16Œª16Ω¯÷∆*/
long long char_to_hex(char x_128[32], int m) {
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
/************************Ω¯÷∆◊™ªª**************************/

/**********************SPN‘ˆ«øº”√‹*************************/
/*64±»Ãÿ√˜Œƒº”°¢Ω‚√‹s∫–(ƒÊ£©¥˙ªª*/
long long s_arrange(long long u, int S[16][16]) {   //º”√‹ ±”√S£¨Ω‚√‹”√S_inverse
    int i;
    long long v = 0;
    long long t0[8] = {0xff00000000000000, 0x00ff000000000000, 0x0000ff0000000000, 0x000000ff00000000,
                       0x00000000ff000000, 0x0000000000ff0000, 0x000000000000ff00,
                       0x00000000000000ff};//“ªπ≤64Œª√˜Œƒ£¨∑÷Œ™8◊È
    long long t[8];
    int low, high, swap;
    for (i = 0; i < 8; i++)
        t[i] = (u & t0[i]) >> (56 - i * 8);       //∞—u÷–µƒ√ø16Œª¥Ê∑≈‘⁄t[i]÷–£¨∏ﬂŒª‘⁄◊Ó◊Û£¨–Ë“™”““∆56Œª£¨“‘¥À¿‡Õ∆
    for (i = 0; i < 8; i++) {
        low = (t[i] & 0x0f);
        high = (t[i] & 0xf0) >> 4;
        swap = S[high][low];                //Ω´t[i]÷–¡Ω∏ˆ16Ω¯÷∆ ˝£¨◊˜Œ™S ˝◊Èµƒ––¡–Ω¯––ÃÊªª
        t[i] = (long) swap;
        t[i] = t[i] << (56 - i * 8);            //Ω´t[i]¡¨Ω”≥…64±»Ãÿ
        v = v | t[i];                         //“ÏªÚ¡¨Ω”£¨t[i]√ø“ª∏ˆÀ˘¥¶Œª÷√≤ªÕ¨£¨“ÏªÚº¥ø…¡¨Ω”
    }
    return v;
}

/*º”√‹p÷√ªª*/
long long p_arrange(long long v) {    //p∫–÷√ªª£¨Ω´64Œª ˝æ›∑÷Œ™8◊È
    unsigned long long b[4];
    unsigned long long t[8];                  //Ω´v∑÷Œ™8◊È£¨√ø“ª◊Èµƒ ˝÷µ¥Ê∑≈‘⁄ ˝◊Èt÷–
    t[0] = 0xff00000000000000 & v;
    t[4] = 0x00000000ff000000 & v;
    t[1] = 0x00ff000000000000 & v;
    t[5] = 0x0000000000ff0000 & v;
    t[2] = 0x0000ff0000000000 & v;
    t[6] = 0x000000000000ff00 & v;
    t[3] = 0x000000ff00000000 & v;
    t[7] = 0x00000000000000ff & v;
    v = (t[0] >> 56) | (t[1] >> 24) | (t[2] >> 8) | (t[3] << 24) | (t[4] >> 16) | (t[5]) | (t[6] << 32) | (t[7] << 48);
    //Ω´8◊È ˝æ›∞¥’’p∫–πÊ‘ÚΩªªªŒª÷√£¨÷√ªª,v“ÏªÚ¡¨Ω”
    b[0] = (0x000000000000ffff & v);
    b[1] = (0x00000000ffff0000 & v) >> 16;
    b[2] = (0x0000ffff00000000 & v) >> 32;
    b[3] = (0xffff000000000000 & v) >> 48;
    v = (p_spn(b[3]) << 48) | (p_spn(b[2]) << 32) | (p_spn(b[1]) << 16) | p_spn(b[0]);
    //Ω´8◊È÷√ªª∫Ûµƒ∑÷Œ™4◊È£¨“ª◊È16±»Ãÿ£¨√ø“ª◊ÈΩ¯––‘≠ ºspnµƒ÷√ªª
    return v;
}

/*‘≠ ºP∫–÷√ªª*/
long long p_spn(int u) {
    int i;
    int P_temp[16] = {0};
    int p_bit[16] = {0};
    numTo16Bit(P_temp, u);         //u±‰≥…16Œª∂˛Ω¯÷∆
    for (i = 0; i < 16; i++)
        p_bit[i] = P_temp[Pbox[i]]; //16Œª÷√ªª£¨∞¥’’PboxµƒπÊ‘Ú
    u = bit16ToNum(p_bit);          //÷√ªª∫Ûµƒ16Œª∂˛Ω¯÷∆±‰Œ™u
    u = (long) u;
    return u;
}

/*spn‘ˆ«øº”√‹*/
long long spn_encryption(long long x, long long K) {
    long long y;
    int i;
    KEY_Arr(K, key);      //√‹‘ø±‡≈≈
    w = x;
    for (i = 0; i < Nr - 1; i++) {   //«∞Nr-1¬÷
        u = key[i] ^ w;        //∞◊ªØ
        v = s_arrange(u, S);  //¥˙ªª
        w = p_arrange(v);    //÷√ªª
    }
    u = key[Nr - 1] ^ w;
    v = s_arrange(u, S);
    y = key[Nr] ^ v;       //◊Ó∫Û“ª¬÷“ÏªÚ£¨≤ª÷√ªª
    return y;
}
/**********************SPN‘ˆ«øº”√‹*************************/

/**********************SPN‘ˆ«øΩ‚√‹*************************/
/*Ω‚√‹ π”√s∫–µƒƒÊ*/
void sbox_inverse(int S[16][16], int S_inverse[16][16]) {
    int i, j, temp, th, tl;
    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++) {
            temp = S[i][j];
            th = (temp & 0xf0) >> 4;    //thŒ™∏ﬂÀƒŒª
            tl = temp & 0x0f;         //tlŒ™µÕÀƒŒª
            temp = (i << 4) | j;          //i◊˜Œ™∏ﬂÀƒŒª£¨j◊˜Œ™µÕÀƒŒª£¨◊˜Œ™sƒÊµƒ‘™Àÿ
            S_inverse[th][tl] = temp; //th£¨tlŒ™tempµƒŒª÷√
        }       //º”√‹¥˙ªª ±£¨Ω´u÷–ƒ⁄»›±‰≥…s––¡–»ª∫Û”√sµƒƒ⁄»›¥˙ªª£¨Ω‚√‹ ±Ω´s––¡–±‰≥…s_inverseƒ⁄»›£¨s÷–µƒƒ⁄»›±‰Œ™––¡–
}

/*64bit√‹ŒƒΩ‚√‹p∫–ƒÊ÷√ªª*/
long long p_inverse(long long u) {  //p∫–ƒÊ÷√ªª£¨Ω´64Œª ˝æ›∑÷Œ™8◊È
    unsigned long long b[4];
    unsigned long long t[8];
    b[0] = (0x000000000000ffff & u);
    b[1] = (0x00000000ffff0000 & u) >> 16;
    b[2] = (0x0000ffff00000000 & u) >> 32;
    b[3] = (0xffff000000000000 & u) >> 48;
    u = (p_spn(b[3]) << 48) | (p_spn(b[2]) << 32) | (p_spn(b[1]) << 16) | p_spn(b[0]);
    //Ω´8◊È÷√ªª∫Ûµƒ∑÷Œ™4◊È£¨“ª◊È16±»Ãÿ£¨√ø“ª◊ÈΩ¯––‘≠ ºspnµƒƒÊ÷√ªª£¨ƒÊ÷√ªª”Î÷√ªªœ‡Õ¨
    t[0] = 0xff00000000000000 & u;
    t[4] = 0x00000000ff000000 & u;
    t[1] = 0x00ff000000000000 & u;
    t[5] = 0x0000000000ff0000 & u;
    t[2] = 0x0000ff0000000000 & u;
    t[6] = 0x000000000000ff00 & u;
    t[3] = 0x000000ff00000000 & u;
    t[7] = 0x00000000000000ff & u;
    u = (t[0] >> 24) | (t[1] >> 48) | (t[2] >> 32) | (t[3] << 8) | (t[4] << 24) | (t[5]) | (t[6] << 16) | (t[7] << 56);
    //Ω´8◊È ˝æ›∞¥’’p∫–πÊ‘ÚΩªªªŒª÷√£¨ƒÊ÷√ªª
    return u;
}

/*spn‘ˆ«øΩ‚√‹*/
long long spn_dncryption(long long y, long long K) {
    long long x;
    int i;
    KEY_Arr(K, key);
    sbox_inverse(S, S_inverse);//ƒÊ¥˙ªª
    v = key[16] ^ y;              //√‹‘ø“ÏªÚ
    u = s_arrange(v, S_inverse); //ƒÊ¥˙ªª
    w = key[15] ^ u;              //∞◊ªØ
    for (i = 0; i < Nr - 1; i++) {
        v = p_inverse(w);       //ƒÊ÷√ªª
        u = s_arrange(v, S_inverse);
        w = key[Nr - i - 2] ^ u;
    }
    x = w;
    return x;
}
/**********************SPN‘ˆ«øΩ‚√‹*************************/
