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
#ifndef CUSTOMUTIL_H
#define CUSTOMUTIL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "ecc.h"   // 确保 ecc.h 中定义了 struct Point

/* 输出十六进制数据，用于调试 */
void print_hex(const char *label, const uint8_t *data, size_t len);

/**
 * generate_strpublickey - 生成公钥的十六进制字符串表示
 *
 * @publickey: 输入 ECC 公钥（使用 struct Point*）
 * @compress: 如果为 true，则生成压缩格式；否则生成非压缩格式
 * @dst: 输出缓冲区，要求足够大（压缩格式至少 67 字节，非压缩至少 131 字节）
 */
void generate_strpublickey(struct Point *publickey, bool compress, char *dst);


/**
 * hexs2bin - 将十六进制字符串转换为二进制数据
 *
 * @hex: 输入的十六进制字符串（例如 "04abcd..."）
 * @out: 输出的二进制数据缓冲区（调用者需确保空间足够）
 *
 * 返回转换后的字节数，出错时返回 0。
 */
int hexs2bin(const char *hex, unsigned char *out);

/* 以下为字符串处理相关工具函数 */

typedef struct str_tokenizer {
    int current;
    int n;
    char **tokens;
} Tokenizer;

typedef struct str_list {
    int n;
    char **data;
    int *lengths;
} List;

char *ltrim(char *str, const char *seps);
char *rtrim(char *str, const char *seps);
char *trim(char *str, const char *seps);
int indexOf(char *s, const char **array, int length_array);
int hasMoreTokens(Tokenizer *t);
char *nextToken(Tokenizer *t);
void stringtokenizer(char *data, Tokenizer *t);
void freetokenizer(Tokenizer *t);
char *tohex(char *ptr, int length);
void tohex_dst(char *ptr, int length, char *dst);

int hexchr2bin(char hex, char *out);

void addItemList(char *data, List *l);
int isValidHex(char *data);

#endif /* CUSTOMUTIL_H */

