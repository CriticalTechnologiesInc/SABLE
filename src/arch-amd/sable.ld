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
  g_begin = .;

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

  .data : { *(.data) }
  g_sl_end = .;
  .bss : { *(.bss) }

  .stack :
  {
    FILL(0x00000000); /* zero initialize for extra security */
    . = ALIGN(0x10000) - 1;
    g_stack_top = .;
    ASSERT(SIZEOF(.stack) >= 4K, "Not enough space in SLB for stack");
  }

  g_end = .;

  /* This section isn't necessary to build the ELF image, we just use it
   * to trigger the assertion only when debugging is disabled */
  .debug_info :
  {
    *(.debug_info);
    ASSERT(SIZEOF(.debug_info) > 0 ? 1 : g_end < g_begin + 64K,
      "SLB is larger than 64K!");
  }

  /DISCARD/ :
  {
    *(.comment);
  }
}
