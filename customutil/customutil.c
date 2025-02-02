/*
 * Copyright (c) 2021, Luis Alberto
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gmp.h>

#include "customutil.h"

/*---------------------------
  调试用函数：输出十六进制数据
---------------------------*/
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

/*---------------------------
  生成公钥的 16 进制字符串表示
  对于压缩格式：如果 y 的最低位为 0，则前缀为 "02"，否则为 "03"；输出 x 坐标的 16 进制字符串；
  对于非压缩格式：前缀 "04" 后跟 x 和 y 坐标的 16 进制字符串。
---------------------------*/
void generate_strpublickey(struct Point *publickey, bool compress, char *dst) {
    memset(dst, 0, compress ? 67 : 131);
    if (compress) {
        if (mpz_tstbit(publickey->y, 0) == 0)
            gmp_snprintf(dst, 67, "02%0.64Zx", publickey->x);
        else
            gmp_snprintf(dst, 67, "03%0.64Zx", publickey->x);
    } else {
        gmp_snprintf(dst, 131, "04%0.64Zx%0.64Zx", publickey->x, publickey->y);
    }
}

/*---------------------------
  将十六进制字符串转换为二进制数据
---------------------------*/
int hexs2bin(const char *hex, unsigned char *out) {
    int len;
    char b1, b2;
    int i;

    if (hex == NULL || *hex == '\0' || out == NULL)
        return 0;

    len = strlen(hex);
    if (len % 2 != 0)
        return 0;
    len /= 2;

    memset(out, 0, len);
    for (i = 0; i < len; i++) {
        if (!hexchr2bin(hex[i*2], &b1) || !hexchr2bin(hex[i*2+1], &b2)) {
            return 0;
        }
        out[i] = (b1 << 4) | b2;
    }
    return len;
}

/*---------------------------
  将单个十六进制字符转换为对应数字
---------------------------*/
int hexchr2bin(char hex, char *out) {
    if (out == NULL)
        return 0;
    if (hex >= '0' && hex <= '9') {
        *out = hex - '0';
    } else if (hex >= 'A' && hex <= 'F') {
        *out = hex - 'A' + 10;
    } else if (hex >= 'a' && hex <= 'f') {
        *out = hex - 'a' + 10;
    } else {
        return 0;
    }
    return 1;
}

/*---------------------------
  以下为字符串处理相关工具函数
---------------------------*/
char *ltrim(char *str, const char *seps) {
    size_t totrim;
    if (seps == NULL) {
        seps = "\t\n\v\f\r ";
    }
    totrim = strspn(str, seps);
    if (totrim > 0) {
        size_t len = strlen(str);
        if (totrim == len) {
            str[0] = '\0';
        } else {
            memmove(str, str + totrim, len + 1 - totrim);
        }
    }
    return str;
}

char *rtrim(char *str, const char *seps) {
    int i;
    if (seps == NULL) {
        seps = "\t\n\v\f\r ";
    }
    i = strlen(str) - 1;
    while (i >= 0 && strchr(seps, str[i]) != NULL) {
        str[i] = '\0';
        i--;
    }
    return str;
}

char *trim(char *str, const char *seps) {
    return ltrim(rtrim(str, seps), seps);
}

int indexOf(char *s, const char **array, int length_array) {
    int index = -1;
    for (int i = 0; i < length_array; i++) {
        if (strcmp(s, array[i]) == 0) {
            index = i;
            break;
        }
    }
    return index;
}

/* Tokenizer 函数实现 */
int hasMoreTokens(Tokenizer *t) {
    return (t->current < t->n);
}

char *nextToken(Tokenizer *t) {
    if (t->current < t->n) {
        return t->tokens[t->current++];
    } else {
        return NULL;
    }
}

void stringtokenizer(char *data, Tokenizer *t) {
    char *token;
    t->tokens = NULL;
    t->n = 0;
    t->current = 0;
    trim(data, "\t\n\r ");
    token = strtok(data, " \t:");
    while (token != NULL) {
        t->n++;
        t->tokens = (char**) realloc(t->tokens, sizeof(char*) * t->n);
        if (t->tokens == NULL) {
            printf("Out of memory\n");
            exit(0);
        }
        t->tokens[t->n - 1] = token;
        token = strtok(NULL, " \t");
    }
}

void freetokenizer(Tokenizer *t) {
    if (t->n > 0) {
        free(t->tokens);
    }
    memset(t, 0, sizeof(Tokenizer));
}

/* 将数据转换为十六进制字符串，返回新分配的缓冲区，调用者负责释放 */
char *tohex(char *ptr, int length) {
    char *buffer;
    int offset = 0;
    unsigned char c;
    buffer = (char *) malloc((length * 2) + 1);
    for (int i = 0; i < length; i++) {
        c = ptr[i];
        sprintf(buffer + offset, "%.2x", c);
        offset += 2;
    }
    buffer[length * 2] = '\0';
    return buffer;
}

void tohex_dst(char *ptr, int length, char *dst) {
    int offset = 0;
    unsigned char c;
    for (int i = 0; i < length; i++) {
        c = ptr[i];
        sprintf(dst + offset, "%.2x", c);
        offset += 2;
    }
    dst[length * 2] = '\0';
}

/* List 函数实现 */
void addItemList(char *data, List *l) {
    l->data = (char**) realloc(l->data, sizeof(char*) * (l->n + 1));
    l->data[l->n] = data;
    l->n++;
}

int isValidHex(char *data) {
    char c;
    int len, valid = 1;
    len = strlen(data);
    for (int i = 0; i < len && valid; i++) {
        c = data[i];
        valid = ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'));
    }
    return valid;
}

