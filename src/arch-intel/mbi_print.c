#include "util.h"
#include "types.h"
#include "multiboot.h"
#include "keyboard.h"
#include "mbi.h"

void _print_mbi(const multiboot_info_t *mbi)
{
	/* print mbi for debug */
	unsigned int i, j;

	out_description("print mbi at ", (unsigned int) mbi);
	out_description("flags:", mbi->flags);

	if (mbi->flags & MBI_MEMLIMITS) {
		out_description("mem_lower ", mbi->mem_lower);
		out_description("mem_upper ", mbi->mem_upper);
	} else {
		out_info("Skipping MBI_MEMLIMITS not set");
	}

	if (mbi->flags & MBI_BOOTDEV) {
		out_description("boot_device.bios_driver 8bit ", mbi->boot_device.bios_driver);
		out_description("boot_device.top_level_partition 8bit ", mbi->boot_device.top_level_partition);
		out_description("boot_device.sub_partition 8bit ", mbi->boot_device.sub_partition);
		out_description("boot_device.third_partition 8bit ", mbi->boot_device.third_partition);
	} else {
		out_info("skipping MBI_BOOTDEV not set");
	}

	if (mbi->flags & MBI_CMDLINE ) {
		out_info("MBI_CMDLINE is set: Skipping printing cmd line now as it creates infinite loop");
	} else {
		out_info("MBI_MEMLIMITS is not set");
	}

	if ( mbi->flags & MBI_MODULES ) {
		out_description("mods_count", mbi->mods_count);
		out_description("mods_addr", mbi->mods_addr);
		for (i = 0; i < mbi->mods_count; i++) {
			module_t *p = (module_t *)(mbi->mods_addr + i * sizeof(module_t));
			out_description("module num", i);
			out_description("mod_start", p->mod_start);
			out_description("mod_end", p->mod_end);
		}
	} else {
		out_info("skipping MBI_MODULES is not set");
	}

	if (mbi->flags & MBI_AOUT ) {
		const aout_t *p = &(mbi->syms.aout_image);
		out_description("aout : tabsize", p->tabsize);
		out_description("strsize", p->strsize);
		out_description("addr", p->addr);
	} else {
		out_info("Skipping MBI_AOUT not set");
	}

	if ( mbi->flags & MBI_ELF ) {
		const elf_t *p = &(mbi->syms.elf_image);
		out_description("num", p->num);
		out_description("size", p->size);
		out_description("add", p->addr);
		out_description("shndx", p->shndx);
	} else {
		out_info("skipping MBI_ELF is not set");
	}

	if (mbi->flags & MBI_MEMMAP) {
		memory_map_t *p;
		out_description("mmap_length", mbi->mmap_length);
		out_description("mmap_addr", mbi->mmap_addr);

		j = 0;
		for (p = (memory_map_t *)mbi->mmap_addr;
			(uint32_t)p < mbi->mmap_addr + mbi->mmap_length;
			p =(memory_map_t *)((uint32_t)p + p->size + sizeof(p->size))) {
				out_description("Entry", j);
				out_description("size", p->size);
				out_description("base_addr_high", p->base_addr_high);
				out_description("base_addr_low", p->base_addr_low);
				out_description("length_high", p->length_high);
				out_description("length_low", p->length_low);
				out_description("type", p->type);
				j++;
		}
	}

	if (mbi->flags & MBI_DRIVES) {
		out_description("drives_length", mbi->drives_length);
		out_description("drives_addr", mbi->drives_addr);
	} else {
		out_info("skipping MBI_DRIVES not set");
	}

	if ( mbi->flags & MBI_CONFIG ) {
		out_description("config_table", mbi->config_table);
	} else {
		out_info("skipping MBI_CONFIG not set");
	}

	if ( mbi->flags & MBI_BTLDNAME ) {
		out_description("boot_loader_name",  mbi->boot_loader_name);
		for(j = 0; j  < 10; j++) {
			out_char(mbi->boot_loader_name + j);
		}
	} else {
		out_info("skipping MBI_BTLDNAME not set");
	}

	if ( mbi->flags & MBI_APM ) {
		out_description("apm_table", mbi->apm_table);
	} else {
		out_info("skipping MBI_APM not set");
	}

	if ( mbi->flags & MBI_VBE ) {
		out_description("vbe_control_info", mbi->vbe_control_info);
		out_description("vbe_mode_info", mbi->vbe_mode_info);
		out_description("vbe_mode", mbi->vbe_mode);
		out_description("vbe_interface_seg", mbi->vbe_interface_seg);
		out_description("vbe_interface_off", mbi->vbe_interface_off);
		out_description("vbe_interface_len", mbi->vbe_interface_len);
	}
}

void print_mbi(struct mbi *mbi) {
	_print_mbi((multiboot_info_t *) mbi);	
}
