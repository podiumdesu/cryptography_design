//
// Created by PetnaKanojo on 2018/9/11.
//

#ifndef CRYPTOGRAPHY_MYLIB_H
#define CRYPTOGRAPHY_MYLIB_H


void gentable(int n, int s, FILE *file);
void printhex(unsigned char *input);
void writefile(FILE *file, unsigned char *array, int n);
void printHexWithBytes(unsigned char *input, int bytes);
void sha1hash(unsigned char *key, unsigned char *ciphertext);
void reduction(unsigned char *ciphertext, unsigned char *key, int n, int seed);
unsigned long binarytonum(unsigned char *binary);
unsigned long power(unsigned long a, int power);
void assign(unsigned char *pass, unsigned long val);
void pad(unsigned char *topad, unsigned char *padded);
void crack(int n, int s, unsigned long rows, unsigned char (*table)[2][16], unsigned char *hash);
void deepcopy(unsigned char *copy, unsigned char *paste);
int equals(unsigned char *a, unsigned char *b);

#endif //CRYPTOGRAPHY_MYLIB_H
