/*
 * hash.h:  definition of and support fns for tb_hash_t type
 *
 * Copyright (c) 2006-2007, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of the Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef __HASH_H__
#define __HASH_H__

#define TB_HALG_SHA1_LG 0x0000  /* legacy define for SHA1 */
#define TB_HALG_SHA1    0x0004 
#define TB_HALG_SHA256  0x000B 
#define TB_HALG_SM3     0x0012 
#define TB_HALG_SHA384  0x000C
#define TB_HALG_SHA512  0x000D
#define TB_HALG_NULL    0x0010

#define SHA1_LENGTH        20
#define SHA256_LENGTH      32
#define SM3_LENGTH         32
#define SHA384_LENGTH      48
#define SHA512_LENGTH      64 

typedef uint8_t sha1_hash_t[SHA1_LENGTH];
typedef uint8_t sha256_hash_t[SHA256_LENGTH];
typedef uint8_t sm3_hash_t[SM3_LENGTH];
typedef uint8_t sha384_hash_t[SHA384_LENGTH];
typedef uint8_t sha512_hash_t[SHA512_LENGTH];

typedef union {
    uint8_t    sha1[SHA1_LENGTH];
    uint8_t    sha256[SHA256_LENGTH];
    uint8_t    sm3[SM3_LENGTH];
    uint8_t    sha384[SHA384_LENGTH];
} tb_hash_t;

#endif    /* __HASH_H__ */
//
//
///*
// * Local variables:
// * mode: C
// * c-set-style: "BSD"
// * c-basic-offset: 4
// * tab-width: 4
// * indent-tabs-mode: nil
// * End:
// */



/*
 * state that must be saved across S3 and will be sealed for integrity
 * before extending PCRs and launching kernel
 */ 
#define MAX_VL_HASHES 32
#define MAX_ALG_NUM 5 
     

/*
 *	we can remove following structure just copying to avoid compilation error
 */

typedef struct {
	uint16_t  alg;
	tb_hash_t hash;
} hash_entry_t;

typedef struct {
	uint32_t  count;
	hash_entry_t entries[MAX_ALG_NUM];
} hash_list_t;

