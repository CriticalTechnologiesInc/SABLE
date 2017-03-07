/*
 * \brief   A size optimized SHA1 variant, hashes up to 512MB.
 * \date    2006-03-28
 * \author  Bernhard Kauer <kauer@tudos.org>
 */
/*
 * Copyright (C) 2006,2007,2010  Bernhard Kauer <kauer@tudos.org>
 * Technische Universitaet Dresden, Operating Systems Research Group
 *
 * This file is part of the OSLO package, which is distributed under
 * the  terms  of the  GNU General Public Licence 2.  Please see the
 * COPYING file for details.
 */

#ifndef ISABELLE
#include "asm.h"
#include "alloc.h"
#include "sha.h"
#include "util.h"

#define ROL(VALUE, COUNT) ((VALUE) << COUNT | (VALUE) >> (32 - COUNT))

/*
 * Get a w value.
 *
 * Note: we modify value inflight, to avoid an additional array.
 */
inline static unsigned int get_w(unsigned char *value, unsigned int round) {
  unsigned int res;
  unsigned int *w = (unsigned int *)value;
  if (round >= 16) {
    w[16] = ROL(w[13] ^ w[8] ^ w[2] ^ w[0], 1);
    res = w[16];
    for (unsigned i = 0; i < 16; i++)
      w[i] = w[i + 1];
    return res;
  } else {
    w[round] = ntohl(w[round]);
    return w[round];
  }
}

/**
 * Process a single block of 512 bits.
 */
static void process_block(SHA1_Context *ctx) {
  unsigned int i;
  unsigned int X[6];
  unsigned int tmp;

  for (i = 0; i < 5; i++)
    X[i + 1] = ntohl(((unsigned int *)ctx->hash.digest)[i]);

  for (i = 0; i < 80; i++) {
    tmp = X[3] ^ X[4];
    if (i < 40) {
      if (i < 20)
        tmp = (X[4] ^ (X[2] & tmp)) + 0x5A827999;
      else
        tmp = (tmp ^ X[2]) + 0x6ED9EBA1;
    } else if (i < 60)
      tmp = ((X[2] & X[3]) | (X[2] & X[4]) | (X[3] & X[4])) + 0x8F1BBCDC;
    else
      tmp = (X[2] ^ tmp) + 0xCA62C1D6;

    X[0] = tmp + ROL(X[1], 5) + X[5] + get_w(ctx->buffer, i);
    X[2] = ROL(X[2], 30);
    for (int j = 5; j > 0; j--)
      X[j] = X[j - 1];
  }

  /* we store the hash in big endian - this avoids a loop at the end... */
  for (i = 0; i < 5; i++)
    ((unsigned int *)ctx->hash.digest)[i] =
        ntohl(ntohl(((unsigned int *)ctx->hash.digest)[i]) + X[i + 1]);
}

/**
 * @param ctx    - store immediate values like unprocessed bytes and the overall
 * length
 */
void sha1_init(SHA1_Context *ctx) {
  ctx->index = 0;
  ctx->blocks = 0;

  ((UINT32 *)ctx->hash.digest)[0] = 0x01234567;
  ((UINT32 *)ctx->hash.digest)[1] = 0x89ABCDEF;
  ((UINT32 *)ctx->hash.digest)[2] = 0xFEDCBA98;
  ((UINT32 *)ctx->hash.digest)[3] = 0x76543210;
  ((UINT32 *)ctx->hash.digest)[4] = 0xf0e1d2c3;
}

/**
 * EXCEPT: ERROR_SHA1_DATA_SIZE
 *
 * Hash a count bytes from value.
 *
 * @param ctx    - store immediate values like unprocessed bytes and the overall
 * length
 * @param value  - a string to hash
 * @param count  - the number of characters in value
 */
RESULT sha1(SHA1_Context *ctx, const void *val, UINT32 count) {
  RESULT ret = { .exception.error = NONE };
  const BYTE *value = val;
  for (; count + ctx->index >= 64;
       count -= 64 - ctx->index, value += 64 - ctx->index, ctx->index = 0) {
    memcpy(ctx->buffer + ctx->index, value, 64 - ctx->index);
    process_block(ctx);
    ctx->blocks++;
    ERROR(ctx->blocks >= 1 << 23, ERROR_SHA1_DATA_SIZE, "SHA data exceeds maximum size");
  }

  memcpy(ctx->buffer + ctx->index, value, count);
  ctx->index += count;
  return ret;
}

/**
 * Finish the operation. The output is available in ctx->hash.
 */
void sha1_finish(SHA1_Context *ctx) {
  ctx->buffer[ctx->index] = 0x80;
  for (unsigned i = ctx->index + 1; i < 64; i++)
    ctx->buffer[i] = 0;

  if (ctx->index > 55) {
    process_block(ctx);
    for (unsigned i = 0; i < 64; i++)
      ctx->buffer[i] = 0;
  }

  /* using a 32bit value for blocks and not using the upper bits of
     tmp limits the maximum hash size to 512 MB. */
  unsigned long long tmp = (ctx->blocks << 9) + (ctx->index << 3);
  ((unsigned long *)ctx->buffer)[15] = ntohl(tmp & 0xffffffff);
  process_block(ctx);
}
#endif
