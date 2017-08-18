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

#pragma once

#include "tpm/platform.h"

struct SHA1_Context
{
  UINT32 index;
  UINT32 blocks;
  BYTE buffer[64+4];
  BYTE hash[20];
};

void sha1_init(struct SHA1_Context *ctx);
void sha1(struct SHA1_Context *ctx, unsigned char* value, unsigned count);
void sha1_finish(struct SHA1_Context *ctx);
