from pwn import *
import re, time
 
#context.log_level = "debug"
context.binary = "./zwiebel"
 
prompt = "peda$ "
flag = list("\x00" * 0x40)
bits = []
index = []
 
# loop, jmp, and, mov
'''
=> 0x7ffff7fb00d1:  mov    al,BYTE PTR [rax+0x15]
   0x7ffff7fb00d4:  and    al,0x10
'''
 
'''
    0x7ffff7fb00ea:  loop   0x7ffff7fb00e4
    0x7ffff7fb00ec:   jmp    0x7ffff7fb011b
'''
 
def gdb_send(cmd):
    gdb.sendlineafter(prompt, cmd)
 
def decrypt_loop():
    gdb_send("ni")
    gdb.recvuntil("=> ")
    ins1 = gdb.recvline()[:-1]
    ins2 = gdb.recvline()[:-1]
    ins3 = gdb.recvline()[:-1]
    '''
    print ins1
    print ins2[3:]
    print ins3[3:]
    '''
    if "mov" in ins1 and "al,BYTE PTR [rax+" in ins1:
        index.append(ins1.split("+")[1][:-1])
        #bits.append(ins2.split(",")[1])
        bit = ins2.split(",")[1]
        if "je" in ins3:
            gdb_send("ni")
            gdb_send("set $rax=" + bit)
            bits.append(bit)
        if "jne" in ins3:
            gdb_send("ni")
            #gdb_send("set $rax=" + str((~int(bit,0)) & 0xff))
            gdb_send("set $rax=0x00")
            #bits.append(hex((int(bit,0)) & 0xff))
            bits.append("0x00")
        log.info("bits : {}".format(bits))
        log.info("index : {}".format(index))
 
 
    if "loop" in ins1 and "jmp" in ins2:
        gdb_send("b *" + ins2[3:3 + 14])
        gdb_send("c")
 
 
 
gdb = process(["gdb", "-q", "./zwiebel"])
gdb.sendlineafter("peda$ ", "peda set option ansicolor off")
gdb.sendlineafter("peda$ ", "b *0x4007e0")
gdb_send("b *0x0000000000400875")
gdb_send("r")
gdb_send("set $rax=0")
gdb_send("c")
gdb.sendline("A" * 0x20)
gdb_send("si")
 
try:
    while True:
        decrypt_loop()
except:
    print "Exception !"
    length = len(bits)
    for i in xrange(length):
        idx = int(index[i],0)
        flag[idx] = chr(ord(flag[idx]) | int(bits[i],0))
    log.success("flag : " + "".join(flag))
 
gdb.close()
