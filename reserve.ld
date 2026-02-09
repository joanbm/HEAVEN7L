/*
 * Reserve 0x400000..0x42e000 to map the HEAVEN7W executable.
 */
SECTIONS
{
  .h7shim_reserve 0x400000 (NOLOAD) :
  {
    PROVIDE(__h7shim_reserved_start = .);
    . += 0x2E000;
    PROVIDE(__h7shim_reserved_end = .);
  }
}
INSERT BEFORE .text;
