/*
 * \brief   Elf extraction.
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

#include <elf.h>
#include <util.h>

enum {
  EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI,
  TRAMPOLINE_ADDRESS = 0x7c00,
};

static void
byte_out(unsigned char **code, unsigned char byte)
{
  **code = byte;
  (*code)++;
  /* XXX Check overflow. */
}

static void
gen_mov(unsigned char **code, int reg, unsigned constant)
{
  byte_out(code, 0xB8 | reg);
  byte_out(code, constant);
  byte_out(code, constant >> 8);
  byte_out(code, constant >> 16);
  byte_out(code, constant >> 24);
}

static void
gen_jmp_edx(unsigned char **code)
{
  byte_out(code, 0xFF); byte_out(code, 0xE2);
}

static void
gen_elf_segment(unsigned char **code, void *target, void *src, unsigned len,
		unsigned fill)
{
  gen_mov(code, EDI, (unsigned)target);
  gen_mov(code, ESI, (unsigned)src);
  gen_mov(code, ECX, len);
  byte_out(code, 0xF3);         /* REP */
  byte_out(code, 0xA4);         /* MOVSB */
  /* EAX is zero at this point. */
  gen_mov(code, ECX, fill);
  byte_out(code, 0xF3);         /* REP */
  byte_out(code, 0xAA);         /* STOSB */
}

int
start_module(struct mbi *mbi)
{
  if (mbi->mods_count == 0) {
    out_info("No module to start.\n");
    return -1;
  }

  // skip module after loading
  struct module *m  = (struct module *) mbi->mods_addr;
  mbi->mods_addr += sizeof(struct module);
  mbi->mods_count--;
  mbi->cmdline = m->string;

  // switch it on unconditionally, we assume that m->string is always initialized
  mbi->flags |=  MBI_FLAG_CMDLINE;

  // check elf header
  struct eh *elf = (struct eh *) m->mod_start;
  ERROR(-31, *((unsigned *) elf->e_ident) != 0x464c457f || *((short *) elf->e_ident+2) != 0x0101, "ELF header incorrect");
  ERROR(-32, elf->e_type!=2 || elf->e_machine!=3 || elf->e_version!=1, "ELF type incorrect");
  ERROR(-33, sizeof(struct ph) > elf->e_phentsize, "e_phentsize to small");

  unsigned char *code = (unsigned char *) TRAMPOLINE_ADDRESS;

  for (unsigned i=0; i<elf->e_phnum; i++) {
    struct ph *ph = (struct ph *)(m->mod_start + elf->e_phoff+ i*elf->e_phentsize);
    if (ph->p_type != 1)
      continue;
    gen_elf_segment(&code, ph->p_paddr, (void *)(m->mod_start+ph->p_offset), ph->p_filesz,
		    ph->p_memsz - ph->p_filesz);
  }

  gen_mov(&code, EAX, 0x2BADB002);
  gen_mov(&code, EDX, (unsigned)elf->e_entry);
  gen_jmp_edx(&code);

  asm volatile  ("jmp *%%edx" :: "a" (0), "d" (TRAMPOLINE_ADDRESS), "b" (mbi));

  /* NOT REACHED */
  return 0;
}

/* EOF */
