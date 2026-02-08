SECTIONS
{
  . = 0x400000;

  /* Reserve 0x400000 - 0x500000 for the HEAVEN7W.EXE code */
  .reserved (NOLOAD) :
  {
    __reserved_start = .;
    . += 0x100000;
    __reserved_end = .;
  }

  /* Place the rest of the code right after (in the low 32 bits as well) */
  .text : { *(.text .text.*) }
  .rodata : { *(.rodata .rodata.*) }
  .data : { *(.data .data.*) }
  .bss (NOLOAD) : { *(.bss .bss.* COMMON) }
}
