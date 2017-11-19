# hxp 2017 CTF

**sandb0x**

- There's gcc compile available with user.s assembly code.
- only 80byte length is allowed.
- Remote Binary is blind, and PIE and ASLR are on.
- No way to 2round Exploitation to get shell except for launching shellcode.
- And prctl is used for seccomp filter.
- user.s can overwrite prctl call with `.global prctl;prctl:~~~`
- So, I write shellcode on some stack, and jmp to that address
