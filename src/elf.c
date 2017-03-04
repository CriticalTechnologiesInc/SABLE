/*
 * \brief   Elf extraction.
 * \date    2006-06-07
 * \author  Bernhard Kauer <kauer@tudos.org>
 *
 * \revisions by: robert sutton rpsutton@syr.edu
 * \1. added support for multiboot load : 6 feb 2014
 *
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
#include "exception.h"
#include "mbi.h"
#include "elf.h"
#include "platform.h"
#include "alloc.h"
#include "tcg.h"
#include "util.h"

enum {
  EAX,
  ECX,
  EDX,
  EBX,
  ESP,
  EBP,
  ESI,
  EDI,
  TRAMPOLINE_ADDRESS = 0x7c00,
};

static unsigned char *code = (unsigned char *)TRAMPOLINE_ADDRESS;

static void byte_out(unsigned char byte) {
  *code = byte;
  (code)++;
  /* XXX Check overflow. */
}

static void gen_mov(int reg, unsigned constant) {
  byte_out(0xB8 | reg);
  byte_out(constant);
  byte_out(constant >> 8);
  byte_out(constant >> 16);
  byte_out(constant >> 24);
}

static void gen_jmp_edx() {
  byte_out(0xFF);
  byte_out(0xE2);
}

static void gen_elf_segment(void *target, void *src, unsigned len,
                            unsigned fill) {
  gen_mov(EDI, (unsigned)target);
  gen_mov(ESI, (unsigned)src);
  gen_mov(ECX, len);
  byte_out(0xF3); /* REP */
  byte_out(0xA4); /* MOVSB */
  /* EAX is zero at this point. */
  gen_mov(ECX, fill);
  byte_out(0xF3); /* REP */
  byte_out(0xAA); /* STOSB */
}

RESULT start_module(struct mbi *mbi) {
  RESULT ret = { .exception.error = NONE };
  struct module *m;
  struct mbh *mb;
  struct eh *elf = NULL;

  unsigned load_end;
  unsigned bss_offset;

  unsigned int *elf_magic;
  unsigned short *elf_class_data;

  ERROR(mbi->mods_count == 0, ERROR_NO_MODULE, "No module to start.\n");

  // skip module after loading
  m = (struct module *)mbi->mods_addr;
  mbi->mods_addr += sizeof(struct module);
  mbi->mods_count--;
  mbi->cmdline = m->string;

  // switch it on unconditionally, we assume that m->string is always
  // initialized
  mbi->flags |= MBI_FLAG_CMDLINE;

  // search for multiboot header
  unsigned *ptr;
  for (ptr = (unsigned *)m->mod_start; ptr < (unsigned *)m->mod_start + 8192;
       ptr++)
    if (((struct mbh *)ptr)->magic == MBI_MAGIC1)
      break;
  mb = (struct mbh *)ptr;

  // check if multiboot or ELF load
  if ((mb->flags & 0x00010000) && (mb->magic == MBI_MAGIC1)) {

    // set multiboot load addresses and offsets
    if (mb->load_end_addr == 0) {
      load_end = m->mod_end;
    } else {
      load_end = mb->load_end_addr;
    }
    if (mb->bss_end_addr == 0) {
      bss_offset = 0;
    } else {
      bss_offset = mb->bss_end_addr - load_end;
    }

    // create multiboot segment
    gen_elf_segment(
        (UINT32 *)mb->load_addr,
        ((UINT32 *)mb - ((UINT32 *)mb->header_addr - (UINT32 *)mb->load_addr)),
        load_end - mb->load_addr, bss_offset);

  } else {
    // check elf header

    elf = (struct eh *)m->mod_start;
    elf_magic = (unsigned int *)elf->e_ident;
    elf_class_data = (unsigned short *)(elf->e_ident + 4);
    out_description("elf magic:", *elf_magic);
    out_description("elf class_data:", *elf_class_data);

    ERROR(*elf_magic != 0x464c457f || *elf_class_data != 0x0101,
          ERROR_BAD_ELF_HEADER, "ELF header incorrect");
    ERROR(elf->e_type != 2 || elf->e_machine != 3 || elf->e_version != 1,
          ERROR_BAD_ELF_HEADER, "ELF type incorrect");
    ERROR(sizeof(struct ph) > elf->e_phentsize, ERROR_BAD_ELF_HEADER,
          "e_phentsize to small");

    for (unsigned i = 0; i < elf->e_phnum; i++) {
      struct ph *ph =
          (struct ph *)(m->mod_start + elf->e_phoff + i * elf->e_phentsize);
      if (ph->p_type != 1)
        continue;
      gen_elf_segment(ph->p_paddr, (void *)(m->mod_start + ph->p_offset),
                      ph->p_filesz, ph->p_memsz - ph->p_filesz);
    }
  }

  gen_mov(EAX, MBI_MAGIC2);
  if (elf != NULL) {
    gen_mov(EDX, (unsigned)elf->e_entry);
  } else {
    gen_mov(EDX, (unsigned)mb->entry_addr);
  }

  out_info("jumping to next segment...\n");
  wait(1000);
  gen_jmp_edx();

  asm volatile("jmp *%%edx" ::"a"(0), "d"(TRAMPOLINE_ADDRESS), "b"(mbi));

  /* not reached */
  return ret;
}
#endif
