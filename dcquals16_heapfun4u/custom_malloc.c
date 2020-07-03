ulong * custom_malloc(uint size)

{
  uint remainder;
  ulong **ppuVar1;
  ulong *puVar2;
  uint new_size;
  ulong *local_10;
  
  // Calculates new chunk size in order to fit the aligment
  new_size = size;
  if (size < 0x10) {
    new_size = 0x10;
  }
  if ((new_size & 7) != 0) {
    new_size = ((new_size >> 3) + 1) * 8;
  }


  local_10 = TOPCHUNK_00602558;
  while( true ) {
    if (local_10 == (ulong *)0x0) {
      local_10 = (ulong *)mmap_thing((ulong)new_size);
    }
    ppuVar1 = (ulong **)((long)local_10 + ((*local_10 & 0xfffffffffffffffc) - 8));
    if ((ulong)new_size <= (*local_10 & 0xfffffffffffffffc)) break;
    local_10 = *ppuVar1;
  }


  remainder = ((uint)*local_10 & 0xfffffffc) - new_size;
  *local_10 = *local_10 | 1;
  if (remainder < 0x19) {
    if (TOPCHUNK_00602558 == local_10) {
      TOPCHUNK_00602558 = *ppuVar1;
      if (TOPCHUNK_00602558 != (ulong *)0x0) {
        *(undefined8 *)((*TOPCHUNK_00602558 & 0xfffffffffffffffc) + (long)TOPCHUNK_00602558) = 0;
      }
    }
    else {
      if (ppuVar1[1] != (ulong *)0x0) {
        *(ulong **)((long)ppuVar1[1] + ((*ppuVar1[1] & 0xfffffffffffffffc) - 8)) = *ppuVar1;
      }
      if (*ppuVar1 != (ulong *)0x0) {
        *(ulong **)((long)*ppuVar1 + (**ppuVar1 & 0xfffffffffffffffc)) = ppuVar1[1];
      }
    }
  }


  else {
    *local_10 = (ulong)new_size;
    *local_10 = *local_10 | 1;
    *local_10 = *local_10 | 2;
    puVar2 = (ulong *)((long)(local_10 + 1) + (ulong)new_size);
    *puVar2 = (ulong)remainder - 8;
    if (TOPCHUNK_00602558 == local_10) {
      TOPCHUNK_00602558 = puVar2;
      if (*ppuVar1 != (ulong *)0x0) {
        *(ulong **)((**ppuVar1 & 0xfffffffffffffffc) + (long)*ppuVar1) = puVar2;
      }
    }
    else {
      if (ppuVar1[1] != (ulong *)0x0) {
        *(ulong **)((long)ppuVar1[1] + ((*ppuVar1[1] & 0xfffffffffffffffc) - 8)) = puVar2;
      }
      if (*ppuVar1 != (ulong *)0x0) {
        *(ulong **)((long)*ppuVar1 + (**ppuVar1 & 0xfffffffffffffffc)) = puVar2;
      }
    }
  }
  return local_10 + 1;
}
