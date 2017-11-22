# hxp 2017 CTF

**sandb0x**

- There's gcc compile available with user.s assembly code.
- only 80byte length is allowed.
- Remote Binary is blind, and PIE and ASLR are on.
- No way to 2round Exploitation to get shell except for launching shellcode.
- And prctl is used for seccomp filter.
- user.s can overwrite prctl call with `.global prctl;prctl:~~~`
- So, I write shellcode on some stack, and jmp to that address










**dont_panic**

- check argv[1] length

```
[----------------------------------registers-----------------------------------]
RAX: 0x8
RBX: 0x4fb090 --> 0x0
RCX: 0x7fffffffe570 ("AAAABBBB")
RDX: 0x4ab760 --> 0x47b8a0 (mov    rcx,QWORD PTR fs:0xfffffffffffffff8)
RSI: 0x10
RDI: 0x490e80 --> 0x10
RBP: 0xc42003bf78 --> 0xc42003bfd0 --> 0x0
RSP: 0xc42003be90 --> 0x0
RIP: 0x47b90a (cmp    rax,0x2a)
R8 : 0x208
R9 : 0x0
R10: 0xc420058170 --> 0x4a8976 ("syntax error scanning booleantoo many open files in systemtraceback has leftover defers locals stack map entries for 227373675443232059478759765625MHeap_AllocLocked - bad npagesSIGPROF: profiling alar"...)
R11: 0xc420058170 --> 0x4a8976 ("syntax error scanning booleantoo many open files in systemtraceback has leftover defers locals stack map entries for 227373675443232059478759765625MHeap_AllocLocked - bad npagesSIGPROF: profiling alar"...)
R12: 0x1
R13: 0x18
R14: 0x170
R15: 0x200
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x47b8fc:	mov    QWORD PTR [rsp+0x50],rcx
   0x47b901:	mov    rax,QWORD PTR [rax+0x18]
   0x47b905:	mov    QWORD PTR [rsp+0x48],rax
=> 0x47b90a:	cmp    rax,0x2a
   0x47b90e:	jl     0x47ba23
```

- 0x47ba23 is fail routine. Feature of Fail.
- Find Success Routine
- make script for automation ( check fail or success ) -> Brute force
- success statement is here
```
loc_47B998:
lea     rax, unk_4A8374
mov     [rsp+0F0h+var_48], rax
mov     [rsp+0F0h+var_40], 1Ch
mov     [rsp+0F0h+var_98], 0
mov     [rsp+0F0h+var_90], 0
lea     rax, unk_489D80
```

- `unk_4a8374` : -> `Seems like you got a flag...`
- This is final Success routine.
- So, check `rip` if success address or not.
- result

```
root@ubuntu:/mnt/hgfs/shared/hxp/dont_panic# python solve.py
[*] '/mnt/hgfs/shared/hxp/dont_panic/main_strip'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/usr/bin/gdb': pid 4985
find hAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
find hxAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
find hxpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
find hxp{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
find hxp{kAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
find hxp{k3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
find hxp{k3eAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
find hxp{k3ePAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
find hxp{k3eP_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
find hxp{k3eP_CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
find hxp{k3eP_C4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
find hxp{k3eP_C4lAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
find hxp{k3eP_C4lMAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
find hxp{k3eP_C4lM_AAAAAAAAAAAAAAAAAAAAAAAAAAAA
find hxp{k3eP_C4lM_AAAAAAAAAAAAAAAAAAAAAAAAAAAA
find hxp{k3eP_C4lM_AnAAAAAAAAAAAAAAAAAAAAAAAAAA
find hxp{k3eP_C4lM_AnDAAAAAAAAAAAAAAAAAAAAAAAAA
find hxp{k3eP_C4lM_AnD_AAAAAAAAAAAAAAAAAAAAAAAA
find hxp{k3eP_C4lM_AnD_DAAAAAAAAAAAAAAAAAAAAAAA
find hxp{k3eP_C4lM_AnD_D0AAAAAAAAAAAAAAAAAAAAAA
find hxp{k3eP_C4lM_AnD_D0nAAAAAAAAAAAAAAAAAAAAA
find hxp{k3eP_C4lM_AnD_D0n'AAAAAAAAAAAAAAAAAAAA
find hxp{k3eP_C4lM_AnD_D0n'tAAAAAAAAAAAAAAAAAAA
find hxp{k3eP_C4lM_AnD_D0n't_AAAAAAAAAAAAAAAAAA
find hxp{k3eP_C4lM_AnD_D0n't_PAAAAAAAAAAAAAAAAA
find hxp{k3eP_C4lM_AnD_D0n't_P4AAAAAAAAAAAAAAAA
find hxp{k3eP_C4lM_AnD_D0n't_P4nAAAAAAAAAAAAAAA
find hxp{k3eP_C4lM_AnD_D0n't_P4n1AAAAAAAAAAAAAA
find hxp{k3eP_C4lM_AnD_D0n't_P4n1cAAAAAAAAAAAAA
find hxp{k3eP_C4lM_AnD_D0n't_P4n1c_AAAAAAAAAAAA
find hxp{k3eP_C4lM_AnD_D0n't_P4n1c__AAAAAAAAAAA
find hxp{k3eP_C4lM_AnD_D0n't_P4n1c__GAAAAAAAAAA
find hxp{k3eP_C4lM_AnD_D0n't_P4n1c__G0AAAAAAAAA
find hxp{k3eP_C4lM_AnD_D0n't_P4n1c__G0_AAAAAAAA
find hxp{k3eP_C4lM_AnD_D0n't_P4n1c__G0_iAAAAAAA
find hxp{k3eP_C4lM_AnD_D0n't_P4n1c__G0_i5AAAAAA
find hxp{k3eP_C4lM_AnD_D0n't_P4n1c__G0_i5_AAAAA
find hxp{k3eP_C4lM_AnD_D0n't_P4n1c__G0_i5_SAAAA
find hxp{k3eP_C4lM_AnD_D0n't_P4n1c__G0_i5_S4AAA
find hxp{k3eP_C4lM_AnD_D0n't_P4n1c__G0_i5_S4FAA
find hxp{k3eP_C4lM_AnD_D0n't_P4n1c__G0_i5_S4F3A
find hxp{k3eP_C4lM_AnD_D0n't_P4n1c__G0_i5_S4F3}
hxp{k3eP_C4lM_AnD_D0n't_P4n1c__G0_i5_S4F3}
[*] Stopped process '/usr/bin/gdb' (pid 4985)
```



**revenge_of_the_zwiebel**

- Flag : `hxp{1_5m3ll_l4zyn355}`
