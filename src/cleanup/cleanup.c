/*
 * \brief   Beirut - hashes command lines
 * \date    2006-06-07
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

#include "mbi.h"
#include "elf.h"
#include "util.h"

int
__main(struct mbi *mbi, unsigned flags)
{
  wait(3000);
  out_string("Zeroing out SLB memory\n");
  memset((void *) 0x100000, 0, 0x10000);
  wait(10000);

  return 14;
}
