# hxp 2017 CTF

**sandb0x**

- There's gcc compile available with user.s assembly code.
- only 80byte length is allowed.
- Remote Binary is blind, and PIE and ASLR are on.
- No way to 2round Exploitation to get shell except for launching shellcode.
- And prctl is used for seccomp filter.
- user.s can overwrite prctl call with `.global prctl;prctl:~~~`
- So, I write shellcode on some stack, and jmp to that address










**revenge_of_the_zwiebel**

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
