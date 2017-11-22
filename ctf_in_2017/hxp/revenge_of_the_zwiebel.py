from pwn import *
import re, time

p = gdb = process(["gdb", "-q", "./zwiebel"])
gdb.sendline("peda set option ansicolor off")

#context.log_level = "debug"

fake = "hxp{th15_15_c3rt41nly_n0t_th3_fl4g}"
fake2 = "hxp{where_u_3quenTisTs_naoW?}"
fake3 = "hxp{g0_st4rt_h4x0ring_pl0x}"
fake4 = "hxp{n0th1ng_t0_h1de_h3r3}"
fake5 = "hxp{such_unfl4g_w0wh4x}"

index = []
bits = []
offsets = []

prompt = "=> "

#gdb.sendline("b *0x40065e")
gdb.sendline("b *0x4006a3")

def init(data):
    p.recvuntil("peda$ ")
    gdb.sendline("b *0x433FAC")  # ptrace
    p.recvuntil("peda$ ")
    gdb.sendline("r")
    p.recvuntil("peda$ ")
    gdb.sendline("ni")
    p.recvuntil("peda$ ")
    gdb.sendline("set $rax=0")
    p.recvuntil("peda$ ")
    #gdb.interactive()
    gdb.sendline("c")
    p.recvuntil("peda$ ")
    gdb.sendline(data)

def get_and():
    not_bit = 0
    while True:
        gdb.sendline("ni")
        gdb.recvuntil(prompt, timeout=3)
        res = gdb.recvline()
        res_next = gdb.recvline()
        #print res[:-1]
        if "not" in res and "cl" in res and "and" in res_next:
            not_bit = 1
            #print "not calculation"

        if "and" in res and "cl" in res and "jecxz" in res_next:
            bit = res[:-1].split(",")[1]
            if not_bit == 0:
                bits.append(bit)
            if not_bit == 1:
                bits.append("0x00")
                not_bit = 0
            log.info("offset : {}".format(bits))
            print ""
            p.recvuntil("peda$ ")
            gdb.sendline("set $rcx=0xff")

        if "mov" in res and "BYTE PTR [rax+" in res:
            index.append(res.split("+")[1][:-2])
            log.info("index : {}".format(index))

        if "loop" in res:
            next_ip = res_next.split(":")[0][3:]
            p.recvuntil("peda$ ")
            gdb.sendline("d")
            p.recvuntil("peda$ ")
            gdb.sendline("b *" + next_ip)
            p.recvuntil("peda$ ")
            gdb.sendline("c")

# rax+8, rax+12, rax+17, rax+4, rax+20, rax+3, rax+9, rax+4, rax+6

init("A" * 0x20)
gdb.recvuntil(prompt)
print gdb.recvline()
gdb.sendline("si")

try:
    while True:
        get_and()
except:
    flag = list("\x00" * 0x40)
    print "CALC"
    length = len(bits)
    for i in xrange(length):
        c = ord(flag[int(index[i],0)])
        c |= int(bits[i],0)
        flag[int(index[i],0)] = chr(c)
    print "".join(flag)


gdb.close()
#gdb.interactive()
