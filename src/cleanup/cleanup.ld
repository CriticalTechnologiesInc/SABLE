SECTIONS
{
  ENTRY(__start)

  . = 0x110000;

  .text :
  {
    KEEP(*(.text.__mbheader));
    KEEP(*(.text.__start));
    *(.text .text.*);
    *(.rodata .rodata.*);
    *(.data .data.*);
    *(.bss .bss.*);
  }

  /DISCARD/ :
  {
    *(.comment)
  }
}
