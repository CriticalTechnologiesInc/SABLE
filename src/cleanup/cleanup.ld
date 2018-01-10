SECTIONS
{
  ENTRY(__start)

  . = 0x10000000 - 0x10000;

  .text :
  {
    . = ALIGN(0x10000);
    g_cleanup_begin = .;
    KEEP(*(.text.__mbheader));
    KEEP(*(.text.__start));
    *(.text .text.*);
    *(.rodata .rodata.*);
  }

  .data : { *(.data) }
  .bss : { *(.bss) }

  .stack :
  {
    . = ALIGN(0x10000) - 1;
    g_stack_top = .;
  }

  g_cleanup_end = .;

  /DISCARD/ :
  {
    *(.comment)
  }
}
