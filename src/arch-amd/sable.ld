SECTIONS
{
    /* Note: expression evaulate lazily.  We want to be sure the
     * slb_code contents from asm.S are at very start of the resulting
     * image.  We also need to make sure we don't overflow region low,
     * which we do manually by specifying what input file's contents
     * go where.
     */
  ENTRY(__start)

  . = 0x200000;

  .sl_header :
  {
    . = ALIGN(0x10000);
    g_sl_begin = .;
    SHORT (_skinit - g_sl_begin);
    SHORT (g_sl_end - g_sl_begin);
  }

  .sl :
  {
    KEEP(*(.text.__mbheader));
    KEEP(*(.text.__start));
    KEEP(*(.text._skinit));
    *(.text .text.*);
    *(.rodata .rodata.*);
  }

  . = ALIGN(0x4);
  g_sl_end = .;

  .data : { *(.data) }
  .bss : { *(.bss) }

  /DISCARD/ :
  {
    *(.comment);
  }
}
