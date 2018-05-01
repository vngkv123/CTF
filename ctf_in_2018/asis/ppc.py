from pwn import *
from hashlib import sha256

p = remote("37.139.22.174", "11740")

def proof_of_work():
    chal = ''.join(random.choice(string.letters+string.digits) for _ in xrange(16))
    print chal
    sol = sys.stdin.read(4)
    if len(sol) != 4 or not sha256(chal + sol).hexdigest().startswith('00000'):
        exit()



p.interactive()
