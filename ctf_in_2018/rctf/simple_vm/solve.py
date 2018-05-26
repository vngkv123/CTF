import string

def rev(s):
    return s.decode("hex")[::-1]

_1 = rev("1740471514431810") + rev("1848491f124b1d10")
_2 = rev("5605535157015453") + rev("09580c0a5f58085a")

d = _1 + _2
x = " !\"#$%&'()*+,-./0123456789:;<=>?"

flag = ''

'''
for i in xrange(32):
    flag += chr(ord(d[i]) ^ ord(x[i]))
'''
strings = string.letters + string.digits

for i in xrange(0x20, 0x40):
    for b in strings:
        v1 = ~(ord(b) & i)
        v2 = ~(v1 & i)
        v3 = ~(v1 & ord(b))
        v4 = ~(v2 & v3)
        if v4 == ord(d[i - 0x20]):
            flag += b
            break

print "RCTF{" + flag + "}"
