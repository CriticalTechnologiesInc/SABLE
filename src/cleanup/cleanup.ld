SECTIONS
{
  ENTRY(__start)
  . = 0x200000;

  .text :
  {
    KEEP(*(.text.__mbheader));
    KEEP(*(.text.__start));
    *(.text .text.*);
    *(.rodata .rodata.*);
    *(.data .data.*);
  }

  .bss :
  {
     . = ALIGN(0x1000); 
     *(COMMON);
     *(.bss);
     . = ALIGN(0x80000);
  }


  .debug :
  {
     *(.debug*);
  }


  /DISCARD/ :
  {
    *(.comment)
  }
}
