//
// Created by PetnaKanojo on 2018/9/11.
//

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "outerLib.h"
#include <math.h>
#include "myLib.h"


void crack(int n, int s, unsigned long rows, unsigned char (*table)[2][16], unsigned char *hash) {
    unsigned long bits = 1 << n;
    int i;
    int numreductions;
    int alpha = 8;
    long chainlength = alpha * (1 << (n - s));
    unsigned char targethash[16];
    deepcopy(hash, targethash);
    for (numreductions = 1; numreductions <= chainlength; numreductions++) {
        for (i = 0; i < rows; i++) {
            unsigned char currenthash[16];
            deepcopy(table[i][1], currenthash);
            if (equals(currenthash, hash)) {
                unsigned char suspectedkey[16];
                deepcopy(table[i][0], suspectedkey);
                int k;
                for (k = 0; k <= chainlength; k++) {
                    unsigned char suspectedhash[16];
                    sha1hash(suspectedkey, suspectedhash);
                    if (equals(suspectedhash, targethash)) {
                        printf("HASH碰撞解密后为：");
                        printHexWithBytes(suspectedkey, 16);
                        printf("\n");
                        return;
                    }
                    reduction(suspectedhash, suspectedkey, n, k);
                }
            }

        }
        int j;
        deepcopy(targethash, hash);
        for (j = numreductions; j > 0; j--) {
            int seed = chainlength - j;
            unsigned char plaintext[16];
            reduction(hash, plaintext, n, seed);
            sha1hash(plaintext, hash);
        }

    }
    printf("failed \n");
    return;
}


int equals(unsigned char *a, unsigned char *b) {
    int i;
    for (i = 0; i < 16; i++) {
        if (a[i] != b[i])
            return 0;
    }
    return 1;
}

void deepcopy(unsigned char *copy, unsigned char *paste) {
    int i;
    for (i = 0; i < 16; i++)
        paste[i] = copy[i];
}

void printHexWithBytes(unsigned char *input, int bytes) {
    int i;
    for (i = 0; i < bytes; i++) {
        printf("%02x", input[i]);
    }
}

unsigned long binarytonum(unsigned char *binary) {
    unsigned long output = 0;
    int i;
    for (i = 12; i <= 15; i++) {
        output += binary[i];
        output <<= 8;
    }
    output >>= 8;
    return output;
}

void pad(unsigned char *topad, unsigned char *pass) {
    int i;
    for (i = 15; i >= 12; i--) {
        pass[i] = topad[i - 12];
    }
    for (i = 11; i >= 0; i--)
        pass[i] = 0x00;
}

void assign(unsigned char *pass, unsigned long val) {
    int i;
    for (i = 15; i >= 12; i--) {
        pass[i] = (unsigned char) val & 0xFF;
        val >>= 8;
    }
    for (i = 11; i >= 0; i--)
        pass[i] = 0;
}

void sha1hash(unsigned char *key, unsigned char *ciphertext) {
    aes_context ctx;
    unsigned char plaintext[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00};
    aes_setkey_enc(&ctx, key, 128);
    aes_crypt_ecb(&ctx, AES_ENCRYPT, plaintext, ciphertext);
//    aesevals++;
}

unsigned long power(unsigned long a, int power) {
    while (power > 0) {
        a *= a;
        power--;
    }
    return a;
}

void reduction(unsigned char *ciphertext, unsigned char *key, int n, int seed) {
    unsigned long decimal = binarytonum(ciphertext);
    decimal = (decimal + seed + (power(decimal, seed) % 547)) % (1 << n);
    decimal = decimal & ((1 << n) - 1);
    assign(key, decimal);
}


/****** 生成彩虹表 ********/

void gentable(int n, int s, FILE *file) {
    unsigned long bits = 1 << n;
//    printf("bits = %x", bits);
    unsigned long rows = 1 << s;
    //
    unsigned char *keys = (unsigned char *) calloc(bits, sizeof(unsigned char));
    if (keys == NULL)
        printf("Keys array is null");
    unsigned long i;

    int collisions = 0;
    for (i = 0; i < bits; i++) {   // 2^n 个可能密钥
//        printf("keys[%lu] = %x\n", i, keys[i]);
        if (keys[i] == 0x01) {    // 为了之后进行测试
            continue;
        }
        keys[i] = 0x01;
        unsigned char currentkey[16];
        // i 从 0 ～ 1 << n (2^n)
        assign(currentkey, i);      // 将 i 赋值给当前的 currentkey
        unsigned char fourbytes[4] = {currentkey[12], currentkey[13], currentkey[14], currentkey[15]};
        writefile(file, fourbytes, 4);
        unsigned char lasthash[16];
        int k;
        int alpha = 8;

        // n 为明文所需位数，s为hash链长度？
        for (k = 0; k < alpha * (1 << (n - s)); k++) {
            unsigned char ciphertext[16];
            sha1hash(currentkey, ciphertext);
            unsigned char nextkey[16];
            int seed = k;
            reduction(ciphertext, nextkey, n, seed);
            if (keys[binarytonum(nextkey)] == 0x01) {
                collisions++;   // 碰撞次数++
            }

            keys[binarytonum(nextkey)] = 0x01;
            int p;
            for (p = 0; p < 16; p++)
                currentkey[p] = nextkey[p];
            if (k == alpha * (1 << (n - s)) - 1) {
                sha1hash(nextkey, lasthash);
            }
        }
        writefile(file, lasthash, 16);
    }
    free(keys);
}

void printhex(unsigned char *input) {
    int i;
    for (i = 0; i < 16; i++) {
        printf("%02x", input[i]);
    }
    printf(" \n");
}


void writefile(FILE *file, unsigned char *array, int n) {
    fwrite(array, sizeof(unsigned char), n, file);
}
