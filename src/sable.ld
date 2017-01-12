/**
 * 512-64K Code
 * 64-60K Stack
 * 60-0K  60K of Code
 */

SECTIONS
{
    /* Note: expression evaulate lazily.  We want to be sure the
     * slb_code contents from asm.S are at very start of the resulting
     * image.  We also need to make sure we don't overflow region low,
     * which we do manually by specifying what input file's contents
     * go where.
     */
  ENTRY(__start)

  . = 0x100000;

  .slb_header :
  {
    . = ALIGN(0x10000);
    g_slb_begin = .;
    SHORT (_skinit - g_slb_begin);
    SHORT (g_slb_end - g_slb_begin);
  }

  .slb :
  {
    KEEP(*(.text.__mbheader));
    KEEP(*(.text.__start));
    KEEP(*(.text._skinit));
    *(.text .text.*);
    *(.rodata .rodata.*);
  }

  . = ALIGN(0x4);
  g_slb_end = .;

  .data : { *(.data) }
  .bss : { *(.bss) }

  . = ALIGN(0x4);
  g_bss_end = .;

  /DISCARD/ :
  {
    *(.comment);
  }
}
