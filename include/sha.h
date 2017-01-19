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

#include "platform.h"
#include "tcg.h"

#define SHA1_PROTO_GEN(Type) void sha1_##Type(Type val);

void sha1_init(void);
void sha1_ptr(const void *val, UINT32 count);
SHA1_PROTO_GEN(BYTE);
SHA1_PROTO_GEN(UINT16);
SHA1_PROTO_GEN(UINT32);
SHA1_PROTO_GEN(TPM_DIGEST);
TPM_DIGEST sha1_finish(void);
