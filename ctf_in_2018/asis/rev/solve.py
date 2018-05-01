# -*- coding: utf-8 -*-

import subprocess
from pwn import *
import string
import itertools
'''
def count(flag):
    with open('/tmp/in', 'wb') as f:
        f.write(flag+'\n')

    res = subprocess.check_output('ltrace -fxi ./babyc 2>&1 < /tmp/in',
        shell=True)
    return res.count('SIGILL')


flag = ''
for _ in range(100):
    res = map(lambda f: count(flag+chr(f)), range(0x20, 0x80))
    if res.count(max(res)) != 1:
        flag += '_'
    else:
        ch = chr(0x20 + res.index(max(res)))
        flag += ch

    print max(res), flag
'''

charset = string.letters + string.digits + "{}_!@"
#for x in itertools.product(charset, repeat=3):
while True:
    p = process(["ltrace", "-fxi", "./babyc"])

    sol = ''.join(random.choice(charset) for _ in xrange(3))
    data = sol + "m0vfu3c4t0r!\x00"
    p.sendline(data)
    p.recvuntil("puts")
    res = p.recvline()
    if "Wrong!" in res:
        print "FAIL : " + sol
        p.close()
    else:
        print "SUCCESS : " + sol
        p.interactive()
        p.close()
