st = "xxxxxxxxxxxxxxxx"
xor1 = "1F19141E".decode("hex")
xor2 = "15191142".decode("hex")
xor3 = "0D0C0B19".decode("hex")
xor4 = "0C161D1C".decode("hex")

xor_value = xor1[::-1] + xor2[::-1] + xor3[::-1] + xor4[::-1]
flag = ''
index = 0
for i in st:
    flag += chr(ord(i) ^ ord(xor_value[index]))
    index += 1

print flag
