# Reversing Challenge
**Description**
- View on strings window in IDA, some suspicious strings are exist.
![strings](https://github.com/vngkv123/CTF/blob/master/ctf_in_2015/inc0gnito/insideout/%E1%84%89%E1%85%B3%E1%84%8F%E1%85%B3%E1%84%85%E1%85%B5%E1%86%AB%E1%84%89%E1%85%A3%E1%86%BA%202018-01-25%20%E1%84%8B%E1%85%A9%E1%84%92%E1%85%AE%201.49.07.png)
- I do xref, this program do some simple xor calculation.
- I write a short python code to decrypt it.
```
data = "7D 40 42 06 43 48 42 45 01 49 6C 3E 5F 2D 55 5D 46 5A 27 58 52 4B 7A 61 4E 71 50 48 7F 65 6E 64 6D 57 68 40 5A 6B 76 70 72".replace(" ", "").decode("hex")
flag = ''
for i in xrange(len(data)):
    flag += chr((len(data) - i) ^ ord(data[i]))
print flag
```
- It print a flag directly :)
- `The flag is B1NG_B0NG_is_a_Friend_oF_ours`
