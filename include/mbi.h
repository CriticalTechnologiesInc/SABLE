#ifndef __MBI_H__
#define __MBI_H__

/*
 * \brief   multiboot structures
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

#define MBI_MAGIC1 0x1badb002
#define MBI_MAGIC2 0x2badb002

enum mbi_enum {
  MBI_FLAG_MEM = 0,
  MBI_FLAG_CMDLINE = 2,
  MBI_FLAG_MODS = 3,
  MBI_FLAG_MMAP = 6,
  MBI_FLAG_BOOT_LOADER_NAME = 9,
  MBI_FLAG_VBE = 11,
};

#define CHECK_FLAG(flags, bit) ((flags) & (1 << (bit)))
#define SET_FLAG(flags, bit) flags |= (1 << (bit));

struct mbh {
  unsigned magic;
  unsigned flags;
  unsigned checksum;
  unsigned header_addr;
  unsigned load_addr;
  unsigned load_end_addr;
  unsigned bss_end_addr;
  unsigned entry_addr;
  unsigned mode_type;
  unsigned width;
  unsigned height;
  unsigned depth;
};

struct mbi {
  unsigned flags;
  unsigned mem_lower;
  unsigned mem_upper;
  unsigned boot_device;
  unsigned cmdline;
  unsigned mods_count;
  unsigned mods_addr;
  unsigned dummy0[4];
  unsigned mmap_length;
  unsigned mmap_addr;
  unsigned dummy1[3];
  unsigned boot_loader_name;
};

struct module {
  unsigned mod_start;
  unsigned mod_end;
  unsigned string;
  unsigned reserved;
};

struct mmap {
  unsigned size;
  unsigned long long base __attribute__((packed));
  unsigned long long length __attribute__((packed));
  unsigned type;
};

#endif
