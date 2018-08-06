//
// Created by PetnaKanojo on 2018/8/2.
//

#include <stdio.h>
#include <stdlib.h>
#include "myLib.h"

void f(int n) {
    if(n)
        f(n/2);
    else
        return;
    printf("%d",n%2);
}

void bitPrintf(int n) {
    f(n);
    printf("\n");
}

void putBitIntoArr (unsigned int * desArr, unsigned int ori) {
    // 暂定是16位的。
    
}


// 获得数字的二进制长度   8 => 1000 => 4
int getNumBinaryLen(unsigned int n) {
    int c = 0 ;  // counter
    while (n) {
        ++c ;
        n >>= 1 ;
    }
    return c ;
}


char * stringSplit(char * string, char *delim, int len) { // len左移的数量
    char result[100][5];
    if (len > 0) {
        int i = 0;
        char *temp = malloc(sizeof(char) * 5 * (len / 4));
        strcpy(temp, strtok(string, delim));
        strcat(temp, " ");
        for (int j = 1; j < (len / 4); j++) {
            strcpy(temp, strtok(NULL, delim));
            strcat(temp, " ");
        }
        char *p;
        while((p = strtok(NULL, delim))) {
            strcpy(result[i], p);
            strcat(result[i], " ");
            i++;
        }
        strcpy(result[i], temp);
    } else {
        int i = 0;
        strcpy(result[i], strtok(string, delim));
        strcat(result[i], " ");
        char *p;
        while((p = strtok(NULL, delim))) {
            i++;
            strcpy(result[i], p);
            strcat(result[i], " ");
        }
    }
    return result;
}