import networkx as nx
import ctypes
from pwn import disasm, context, p32, hexdump, fit
from pickle import dumps, loads
from itertools import product
from capstone import *
from z3 import *
from block import Block

context.arch = 'amd64'

with open('nodes', 'rb') as f:
    nodes = loads(f.read())
with open('graph', 'rb') as f:
    g = loads(f.read())

conditional = {}
cond_mnem1 = [0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f]
cond_mnem2 = [('\x0f' + chr(x)) for x in range(0x80, 0x90)]
uncond_mnem1 = [0xe9, 0xeb, 0xc3]
uncond_mnem2 = ['\xff\x04', '\xff\x05']

for n in nodes:
	if n.id != None:
		if ord(n.code[-1]) in uncond_mnem1 or (len(n.code) > 1 and n.code[-2:] in uncond_mnem2):
			conditional[n.id] = False
		elif ord(n.code[-1]) in cond_mnem1 or (len(n.code) > 1 and n.code[-2:] in cond_mnem2):
			conditional[n.id] = True
		else:
			conditional[n.id] = True

trav = nx.dfs_preorder_nodes(g, 0)
chains = []
visited = set()

# gather all contiguous pieces: "chains" of blocks
for t in trav:
	chain = []

	if t in visited:
		continue

	c = t
	while True:
		#print c
		if c in visited:
			idxs = filter(lambda i: chains[i][0] == c, range(len(chains)))
			if not idxs:
				break

			chains[idxs[0]] = chain + chains[idxs[0]]
			chain = []
			break

		chain.append(c)
		succ = list(g.successors(c))
		visited.add(c)
		if len(succ) == 0 or conditional[c] == False:
			break

		c = [s for s in succ if g.edges[c, s]['dirr'] == 'left'][0]
	#print chain
	#print '--------------------'
	if chain:
		chains.append(chain)

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

chain_no = {}
off_in_chain = {}
piece_len = []

for chain in chains:
	print chain
	code = ''.join(nodes[n].code + '\x00' * nodes[n].missing  for n in chain)	
	piece_len.append(len(code))

	insns = md.disasm(code, len(code))
	for insn in insns:
		print insn.mnemonic, insn.op_str
	print '==================================\n'

N = len(chains)
for i in range(N):
	off = 0	
	for c in chains[i]:
		chain_no[c] = i
		off_in_chain[c] = off
		off += len(nodes[c].code) + nodes[c].missing

total_len = sum(piece_len)
print hex(total_len)
piece = [Int('piece%d' % i) for i in range(N)]
solver = z3.Solver()

def abs(x):
    return If(x >= 0,x,-x)

for i in range(N):
	solver.add(piece[i] >= 0)
	solver.add(piece[i] + piece_len[i] <= total_len)
solver.add(piece[0] == 0)

# blocks should not overlap
for (i, j) in product(range(N), range(N)):
	if i < j:
		solver.add(z3.Or((piece[i] + piece_len[i]) <= piece[j], (piece[j] + piece_len[j]) <= piece[i]))

# rules related to the size of offsets betweeen blocks
for i in range(N):
	chain = chains[i]
	print i, chain
	
	for bl in chain:
		succ = list(g.successors(bl))
		if len(succ) == 0:
			break

		if len(succ) == 2:
			target = filter(lambda x: g.edges[bl, x]['dirr'] == 'right', succ)[0]
		else:
			target = succ[0]

		if nodes[bl].missing == 1:
			off_min = 0
			off_max = 0x80
		elif nodes[bl].missing == 4:
			off_min = 0x81
			off_max = 0x80000000
		elif nodes[bl].missing == 0:
			continue
		else:
			assert(False)

		off_in_this = off_in_chain[bl] + len(nodes[bl].code) + nodes[bl].missing
		off_in_target = off_in_chain[target]
		solver.add(abs(piece[i] + off_in_this - (piece[chain_no[target]] + off_in_target)) <= off_max)
		solver.add(abs(piece[i] + off_in_this - (piece[chain_no[target]] + off_in_target)) >= off_min)

# functions called from different sites should have consistent offsets 
# rules for error_oom
solver.add(piece[0] + 0xac + 0xf018 == piece[6] + 0x128 + 0xed9c)
solver.add(piece[0] + 0xac + 0xf018 == piece[18] + 0x43 + 0xebc8)

# rules for print_block_content
solver.add(piece[6] + 0xda + 0xf38a == piece[18] + 0x12 + 0xf199)
solver.add(piece[6] + 0xda + 0xf38a == piece[7] + 0x37 + 0xf03f)

# rules for call_stack_push
off_t_csp = 0xf + 0xfffff66d - 0xffffe438
solver.add(piece[9] + 0x27 + (0xffffe6b5 - 0x100000000) + off_t_csp == 0)

print solver.check()

m = solver.model()
for i in range(N):
	start = m[piece[i]].as_long()
	print 'Piece[%d]: (0x%x, 0x%x)' % (i, start, start + piece_len[i])

# recover code
code_map = {}

for i in range(N):
	chain = chains[i]
	chain_code = ''

	piece_off = m[piece[i]].as_long()

	for bl in chain:
		block_code = nodes[bl].code
			
		succ = list(g.successors(bl))
		if len(succ) != 0 and nodes[bl].missing:
			if len(succ) == 2:
				target = filter(lambda x: g.edges[bl, x]['dirr'] == 'right', succ)[0]
			else:
				target = succ[0]

			repr_size = nodes[bl].missing
			off_in_this = off_in_chain[bl] + len(block_code) + repr_size
			off_in_target = off_in_chain[target]
			off = - (piece_off + off_in_this) + (m[piece[chain_no[target]]].as_long() + off_in_target)
			off = ctypes.c_ubyte(off).value if repr_size == 1 else ctypes.c_uint(off).value

			block_code += chr(off) if repr_size == 1 else p32(off)
		chain_code += block_code
	code_map[piece_off] = chain_code

func_code = fit(code_map, filler='\x90')

with open('traverse.bin', 'wb') as f:
	f.write(func_code)

with open('traverse.code', 'w') as f:
	f.write(disasm(func_code, offset=True))
