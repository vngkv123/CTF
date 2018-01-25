data = "7D 40 42 06 43 48 42 45 01 49 6C 3E 5F 2D 55 5D 46 5A 27 58 52 4B 7A 61 4E 71 50 48 7F 65 6E 64 6D 57 68 40 5A 6B 76 70 72".replace(" ", "").decode("hex")
flag = ''
for i in xrange(len(data)):
    flag += chr((len(data) - i) ^ ord(data[i]))
print flag
