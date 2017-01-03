/**
 * 512-64K Code
 * 64-60K Stack
 * 60-0K  60K of Code
 */

MEMORY
{
    low (rwxai)  : ORIGIN = 0x100000, LENGTH = 64K
    high (rwxai) : ORIGIN = 0x110000, LENGTH = 0x70004
    null (rwxai) : ORIGIN = 0x180004, LENGTH = 0 /* Intentional 0 length */
}


SECTIONS
{
    /* Note: expression evaulate lazily.  We want to be sure the
     * slb_code contents from asm.S are at very start of the resulting
     * image.  We also need to make sure we don't overflow region low,
     * which we do manually by specifying what input file's contents
     * go where.
     */
  ENTRY(__start)

  LOW :
  {
    *(.text)
    *(.data)
    *(.rodata*)
    *(.bss)
    *(.slb.end_of_low) /* not a real variable; only concerned with its address */
    *(.slb.aligned_end_of_low) /* not a real variable; only concerned with its address */
  } >low

  HIGH :
  {
    *(.slb.start_of_high) /* not a real variable; only concerned with its address */
    FILL(0x00000000);
    . = ORIGIN(high) + LENGTH(high) - 4;
    *(.slb.end_of_high) /* not a real variable; only concerned with its address */
  } >high
  /* Code should be built with -fno-common, but if it's not, complain! */

  /*
  ERRONEOUS :
  {
    *(COMMON)
  } >null
  */

  .debug :
  {
     *(.debug*);
  }

  /DISCARD/ :
  {
    *(.comment)
  }
}
