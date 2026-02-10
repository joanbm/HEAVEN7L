/*
 * Reserve 0x400000..0x42e000 to map the HEAVEN7W executable.
 */
SECTIONS
{
  .heaven7l_reserve 0x400000 (NOLOAD) :
  {
    PROVIDE(__heaven7l_reserved_start = .);
    . += 0x2E000;
    PROVIDE(__heaven7l_reserved_end = .);
  }
}
INSERT BEFORE .text;
