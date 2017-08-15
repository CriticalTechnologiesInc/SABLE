
OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(__start)
PHDRS
{
	text PT_LOAD ;
}

SECTIONS
{
	/* Note: expression evaulate lazily.  We want to be sure the
	 * slb_code contents from asm.S are at very start of the resulting
	 * image.  We also need to make sure we don't overflow region low,
	 * which we do manually by specifying what input file's contents
	 * go where.
	 *
	 * BHUSHAN:
	 * for intel we use following layout
	 * 0x800000	= mbi header
	 * 0x801000	= page table and header
	 *		  then sable code
	 * I am trying to be as close as possible to tboot
	 * (that means we ca use original sable.ld)
	 * main aim of modifying linker script is to make .mlept (page table) 4k aligned and
	 * keep it before start of MLE
	 */

	. = 0x800000;	/* 4k aligned */

	.text : {
		*(.tboot_multiboot_header)
	. = ALIGN(4096);
		*(.mlept)

	_mle_start = .;			/* beginning of MLE pages */
		*(.text)
		*(.fixup)
		*(.gnu.warning)
	} :text = 0x9090		/*0x9090 is filled in hole created by align statement*/

	.rodata : {
		*(.rodata)
		*(.rodata.*)
	}

	. = ALIGN(4096);

	_mle_end = .;			/* end of MLE pages */

	.data : {			/* Data */
		*(.data)
		*(.tboot_shared)
		CONSTRUCTORS
	}

	. = ALIGN(4096);

	__bss_start = .;              /* BSS */
	.bss : {
		*(.bss.stack_aligned)
		*(.bss.page_aligned)
		*(.bss)
	}

	_end = . ;

	/DISCARD/ : {
		*(.comment);
	}
}
