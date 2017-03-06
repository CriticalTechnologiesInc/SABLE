#ifndef __SHA_H__
#define __SHA_H__

/*
 * \brief   header of sha.c
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

typedef struct {
  UINT32 index;
  UINT32 blocks;
  BYTE buffer[64 + 4];
  TPM_DIGEST hash;
} SHA1_Context;

void sha1_init(SHA1_Context *ctx);
/* EXCEPT: ERROR_SHA1_DATA_SIZE */
RESULT sha1(SHA1_Context *ctx, const void *val, UINT32 count);
void sha1_finish(SHA1_Context *ctx);

#endif
