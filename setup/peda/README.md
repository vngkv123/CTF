peda
====

PEDA - Python Exploit Development Assistance for GDB

## Enhancements:
* Dereference memory trace
* Basic support for ARMv7 and aarch64
  * register support
  * condition jump support
  * cpsr register support
* Simple support for ppc and mipsel
  * register support
* Recover armv7 dynamic symbol
* Show different register from prev instruction 
* Simple source code context
* heap colorize
* Syscall information in x86/x64
* SROP information in x86/x64
* contextup/contextdown scroll context of code

## Key Features:
* Enhance the display of gdb: colorize and display disassembly codes, registers, memory information during debugging.
* Add commands to support debugging and exploit development (for a full list of commands use `peda help`):
  * `aslr` -- Show/set ASLR setting of GDB
  * `checksec` -- Check for various security options of binary
  * `dumpargs` -- Display arguments passed to a function when stopped at a call instruction
  * `dumprop` -- Dump all ROP gadgets in specific memory range
  * `elfheader` -- Get headers information from debugged ELF file
  * `elfsymbol` -- Get non-debugging symbol information from an ELF file
  * `lookup` -- Search for all addresses/references to addresses which belong to a memory range
  * `patch` -- Patch memory start at an address with string/hexstring/int
  * `pattern` -- Generate, search, or write a cyclic pattern to memory
  * `procinfo` -- Display various info from /proc/pid/
  * `pshow` -- Show various PEDA options and other settings
  * `pset` -- Set various PEDA options and other settings
  * `readelf` -- Get headers information from an ELF file
  * `ropgadget` -- Get common ROP gadgets of binary or library
  * `ropsearch` -- Search for ROP gadgets in memory
  * `searchmem|find` -- Search for a pattern in memory; support regex search
  * `shellcode` -- Generate or download common shellcodes.
  * `skeleton` -- Generate python exploit code template
  * `vmmap` -- Get virtual mapping address ranges of section(s) in debugged process
  * `xormem` -- XOR a memory region with a key

## Installation

    git clone https://github.com/scwuaptx/peda.git ~/peda
    echo "source ~/peda/peda.py" >> ~/.gdbinit
    cp ~/peda/.inputrc ~/
    echo "DONE! debug your program with gdb and enjoy"

## Screenshot
![ARM64](http://i.imgur.com/iValQBY.png)
![source](http://i.imgur.com/SPBVT7q.png)
![syscall](http://i.imgur.com/AU0jixi.png)
![srop](http://i.imgur.com/l6F6k1N.png)
