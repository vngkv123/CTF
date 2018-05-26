import idaapi

def xor_key(start_addr, length, key):
	for i in xrange(length):
		ci = idaapi.get_byte(start_addr + i) ^ key
		idaapi.patch_byte(start_addr + i, ci)


xor_key(0x401482, 0x162, 0x28)
