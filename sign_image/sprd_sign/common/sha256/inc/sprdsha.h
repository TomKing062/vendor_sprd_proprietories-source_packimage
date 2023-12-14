/*
 *     Copyright (c) 2015 SPREADTRUM Communication - All Rights Reserved.
 *
 *     FileName: sprdsha.h
 *         Desc: header file that integrated sha basic operations
 *       Author: Jacky Yang (xinle.yang@spreadtrum.com)
 */

/*
 * Copyright (c) 2001-2007, Tom St Denis
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

#ifndef SPRD_SHA_H
#define SPRD_SHA_H
#include "sprdsec_header.h"
//#include <stdint.h>
//#include <linux/types.h>
#include <string.h>
//#include <malloc.h>
#include <stdio.h>
//#include <common.h>

//#define LTC_SHA1
#define LTC_SHA256
//#define LTC_TEST
struct sha1_state {
	uint64_t length;
	uint32_t state[5], curlen;
	unsigned char buf[64];
};

#ifdef LTC_SHA256
struct sha256_state {
	uint64_t length;
	uint32_t state[8], curlen;
	unsigned char buf[64];
};
#endif

typedef union Hash_state {
	char dummy[1];
#ifdef LTC_SHA256
	struct sha256_state sha256;
#endif
#ifdef LTC_SHA1
	struct sha1_state sha1;
#endif
	void *data;
} hash_state;

#define CRYPT_OK 0
#define CRYPT_INVALID_ARG 1
#define CRYPT_NOP 2

#ifdef LTC_SHA1
int sha1_init(hash_state * md);
int sha1_process(hash_state * md, const unsigned char *in, uint64_t inlen);
int sha1_done(hash_state * md, unsigned char *hash);
#endif

#ifdef LTC_SHA256
int sha256_init(hash_state * md);
int sha256_process(hash_state * md, const unsigned char *in, uint64_t inlen);
int sha256_done(hash_state * md, unsigned char *hash);
void sha256_csum_wd(const unsigned char *input, unsigned int ilen, unsigned char *output, unsigned int chunk_sz);
#endif

#define LTC_ARGCHK(x) if (!(x)) { printf("assert %s at %s , %d\n", #x,  __FILE__,__LINE__);  }
#define MIN(x, y) ( ((x)<(y))?(x):(y) )
/* a simple macro for making hash "process" functions */
#define HASH_PROCESS(func_name, compress_name, state_var, block_size)                       \
int func_name (hash_state * md, const unsigned char *in, uint64_t inlen)               \
{                                                                                           \
    uint64_t n;                                                                        \
    int           err;                                                                      \
    LTC_ARGCHK(md != NULL);                                                                 \
    LTC_ARGCHK(in != NULL);                                                                 \
    if (md-> state_var .curlen > sizeof(md-> state_var .buf)) {                             \
       return CRYPT_INVALID_ARG;                                                            \
    }                                                                                       \
    while (inlen > 0) {                                                                     \
        if (md-> state_var .curlen == 0 && inlen >= block_size) {                           \
           if ((err = compress_name (md, (unsigned char *)in)) != CRYPT_OK) {               \
              return err;                                                                   \
           }                                                                                \
           md-> state_var .length += block_size * 8;                                        \
           in             += block_size;                                                    \
           inlen          -= block_size;                                                    \
        } else {                                                                            \
           n = MIN(inlen, (block_size - md-> state_var .curlen));                           \
           memcpy(md-> state_var .buf + md-> state_var.curlen, in, (size_t)n);              \
           md-> state_var .curlen += n;                                                     \
           in             += n;                                                             \
           inlen          -= n;                                                             \
           if (md-> state_var .curlen == block_size) {                                      \
              if ((err = compress_name (md, md-> state_var .buf)) != CRYPT_OK) {            \
                 return err;                                                                \
              }                                                                             \
              md-> state_var .length += 8*block_size;                                       \
              md-> state_var .curlen = 0;                                                   \
           }                                                                                \
       }                                                                                    \
    }                                                                                       \
    return CRYPT_OK;                                                                        \
}

#define LOAD32H(x, y)                            \
     { x = ((uint64_t)((y)[0] & 255)<<24) | \
           ((uint64_t)((y)[1] & 255)<<16) | \
           ((uint64_t)((y)[2] & 255)<<8)  | \
           ((uint64_t)((y)[3] & 255)); }

#define ROL(x, y) ( (((uint64_t)(x)<<(uint64_t)((y)&31)) | (((uint64_t)(x)&0xFFFFFFFFUL)>>(uint64_t)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define ROLc ROL

#define ROR(x, y) ( ((((uint64_t)(x)&0xFFFFFFFFUL)>>(uint64_t)((y)&31)) | ((uint64_t)(x)<<(uint64_t)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define RORc ROR

#define STORE64H(x, y)                                                                     \
   { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);     \
     (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);     \
     (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);     \
     (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255); }

#define STORE32H(x, y)                                                                     \
     { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);   \
       (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); }
#endif /* SPRD_SHA_H */
