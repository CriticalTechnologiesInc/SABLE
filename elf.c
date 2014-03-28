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

#include <elf.h>
#include <util.h>
#define NULL 0

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
gen_elf_segment(unsigned char **code, void *target, void *src, unsigned len, unsigned fill)
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
    struct module *m;
	struct mbh *mb;
	struct mbh *mb_start;
	struct mbh *mb_end;
	struct eh *elf=NULL;

	unsigned load_end;	
	unsigned bss_offset;
    unsigned char *code;

    unsigned int *elf_magic;
    unsigned short *elf_class_data;

	if (mbi->mods_count == 0) {
		out_info("No module to start.\n");
		return -1;
	}

	// skip module after loading
	m  = (struct module *) mbi->mods_addr;
	mbi->mods_addr += sizeof(struct module);
	mbi->mods_count--;
	mbi->cmdline = m->string;

	// switch it on unconditionally, we assume that m->string is always initialized
	mbi->flags |=  MBI_FLAG_CMDLINE;

	code = (unsigned char *) TRAMPOLINE_ADDRESS;

	//search for multiboot header
    mb_start = (struct mbh *)m->mod_start;
    mb_end = (struct mbh *)m->mod_end;
	for(mb = mb_start; mb < mb_end; mb++)
		if(mb->magic == MBI_MAGIC1)
			break;

	//check if multiboot or ELF load
	if((mb->flags & 0x00010000) && (mb->magic == MBI_MAGIC1)) {

		//set multiboot load addresses and offsets
		if(mb->load_end_addr == 0){
			load_end = m->mod_end;
		} else {
			load_end = mb->load_end_addr;
		}
		if(mb->bss_end_addr == 0){
			bss_offset = 0;
		} else {
			bss_offset = mb->bss_end_addr - load_end;
		}

		//create multiboot segment
		gen_elf_segment(&code, (UINT32 *)mb->load_addr, ((UINT32 *)mb-((UINT32*)mb->header_addr-(UINT32*)mb->load_addr)), load_end-mb->load_addr,bss_offset);
		

	} else {
		// check elf header
		
		elf = (struct eh *) m->mod_start;
        elf_magic = (unsigned int *) elf->e_ident;
        elf_class_data = (unsigned short *) (elf->e_ident + 4);
        out_description("elf magic:", *elf_magic);
        out_description("elf class_data:", *elf_class_data);

		ERROR(-31, *elf_magic != 0x464c457f || *elf_class_data != 0x0101, "ELF header incorrect");
		ERROR(-32, elf->e_type!=2 || elf->e_machine!=3 || elf->e_version!=1, "ELF type incorrect");
		ERROR(-33, sizeof(struct ph) > elf->e_phentsize, "e_phentsize to small");



		for (unsigned i=0; i<elf->e_phnum; i++) {
			struct ph *ph = (struct ph *)(m->mod_start + elf->e_phoff+ i*elf->e_phentsize);
			if (ph->p_type != 1)
				continue;
			gen_elf_segment(&code, ph->p_paddr, (void *)(m->mod_start+ph->p_offset), ph->p_filesz,
					ph->p_memsz - ph->p_filesz);
		}

	}

	gen_mov(&code, EAX, MBI_MAGIC2);
	if(elf!=NULL){
		gen_mov(&code, EDX, (unsigned)elf->e_entry);
	} else {
		gen_mov(&code,EDX,(unsigned)mb->entry_addr);
	}

	out_info("jumping to next segment...\n");
	wait(1000);
	gen_jmp_edx(&code);

	asm volatile  ("jmp *%%edx" :: "a" (0), "d" (TRAMPOLINE_ADDRESS), "b" (mbi));



	/* NOT REACHED */
	return 0;
}
