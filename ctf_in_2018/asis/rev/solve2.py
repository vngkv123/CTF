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
bf_set = ''
#for x in itertools.product(charset, repeat=3):
for _1 in xrange(0x20, 0x80):
    for _2 in xrange(0x20, 0x80):
        for _3 in xrange(0x20, 0x80):
            p = process(["ltrace", "-fxi", "./babyc"])
            sol = chr(_1) + chr(_2) + chr(_3)
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
