# return to dynamic linker exploitation
**Dynamic section**
- `[tag]-[value]` pair
```
Dynamic section at offset 0xf14 contains 24 entries:
  Tag        Type                         Name/Value
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000c (INIT)                       0x804830c
 0x0000000d (FINI)                       0x8048574
 0x00000019 (INIT_ARRAY)                 0x8049f08
 0x0000001b (INIT_ARRAYSZ)               4 (bytes)
 0x0000001a (FINI_ARRAY)                 0x8049f0c
 0x0000001c (FINI_ARRAYSZ)               4 (bytes)
 0x6ffffef5 (GNU_HASH)                   0x80481ac
 0x00000005 (STRTAB)                     0x804823c
 0x00000006 (SYMTAB)                     0x80481cc
 0x0000000a (STRSZ)                      106 (bytes)
 0x0000000b (SYMENT)                     16 (bytes)
 0x00000015 (DEBUG)                      0x0
 0x00000003 (PLTGOT)                     0x804a000
 0x00000002 (PLTRELSZ)                   32 (bytes)
 0x00000014 (PLTREL)                     REL
 0x00000017 (JMPREL)                     0x80482ec
 0x00000011 (REL)                        0x80482e4
 0x00000012 (RELSZ)                      8 (bytes)
 0x00000013 (RELENT)                     8 (bytes)
 0x6ffffffe (VERNEED)                    0x80482b4
 0x6fffffff (VERNEEDNUM)                 1
 0x6ffffff0 (VERSYM)                     0x80482a6
 0x00000000 (NULL)                       0x0
```

**_dl_runtime_resolve -> _dl_fixup**
- JMPREL is important
- before calling _dl_fixup, edx has reloc_offset and eax has link_map structure pointer.
- JMPREL + reloc_offset( edx ) is important
```
   0xf7fee020 <_dl_runtime_resolve+0> push   eax
   0xf7fee021 <_dl_runtime_resolve+1> push   ecx
   0xf7fee022 <_dl_runtime_resolve+2> push   edx
   0xf7fee023 <_dl_runtime_resolve+3> mov    edx, DWORD PTR [esp+0x10]
   0xf7fee027 <_dl_runtime_resolve+7> mov    eax, DWORD PTR [esp+0xc]
 → 0xf7fee02b <_dl_runtime_resolve+11> call   0xf7fe7800 <_dl_fixup>
   ↳  0xf7fe7800 <_dl_fixup+0>    push   ebp
      0xf7fe7801 <_dl_fixup+1>    push   edi
      0xf7fe7802 <_dl_fixup+2>    mov    edi, eax
      0xf7fe7804 <_dl_fixup+4>    push   esi
      0xf7fe7805 <_dl_fixup+5>    push   ebx
      0xf7fe7806 <_dl_fixup+6>    call   0xf7ff272d <__x86.get_pc_thunk.si>
      
gef➤  x/2wx 0x80482ec + 0x10
0x80482fc:	0x0804a014	0x00000307
```
- 0x804a014 is got address 
- first 07 is magic number 
- 2~4byte is used to SYMTAB number
- SYMTAB is 16byte structure
- In above example, symtab address : 0x80481cc
- 16 * 3 + 0x80481cc
```
gef➤  x/2wx 0x80481cc + 48
0x80481fc:	0x0000001f	0x00000000
gef➤  
0x8048204:	0x00000000	0x00000012
gef➤  
0x804820c:	0x00000047
```
- 1st, 5th value is important
- first 0x1f is strtab offset.
- STRTAB + 0x1f -> "puts"
- 5th value is load check value. -> & with 3 ( lowest 2bits )
