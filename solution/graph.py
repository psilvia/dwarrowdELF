from pwn import *
from capstone import *
import networkx as nx
import sys
from pickle import dumps, loads
from block import Block
from merge import *
import md5

def respline(question, answer, ack = None):
    ret1 = None
    ret2 = None
    if question != "":
        ret1 = io.recvuntil(question)
    io.sendline(str(answer))
    if ack:
        ret2 = io.recvuntil(ack)
    return (ret1, ret2)

def apply_directions(d):
	for c in d:
		respline('(< ^ >)', c)

def apply_instructions(ins):
	for d in ins:
		if d in ['<', '>', '^']:
			respline('(< ^ >)', d)
		else:
			respline('(y/n)', d)

def read_header():
	io.recvuntil('Depth:')
	io.recvline()
	io.recvline()
	io.recvline()
	io.recvline()

io = remote('127.0.0.1', 13371)
context.arch = 'amd64'
#context.log_level = 'debug'

if len(sys.argv) > 1 and sys.argv[1] == 'new':
	g = nx.DiGraph()
	nodes = []
	current = 0
	nodes.append(Block(0))
	g.add_node(0)
else:
	try:
		with open('nodes', 'rb') as f:
			nodes = loads(f.read())
		with open('graph', 'rb') as f:
			g = loads(f.read())
	except IOError:
		print 'Usage:'
		print '\tNew traversal:\n\t\tpython %s new' % sys.argv[0]
		print '\tTo continue traversal:\n\t\tpython %s' % sys.argv[0]
		sys.exit(1)

dirr = ''
level_prompts = 0

reset_done(nodes, g)

# Change target function here
tfunc = 'traverse'
merge_init(tfunc)

all_dir_to_func = {'traverse' : '<ny', 'handle_call' : '<ny>>><<>><<><>y'}
all_dir_back = {'traverse' : 'n^<ny', 'handle_call' : '^>y'}

dir_to_func = all_dir_to_func[tfunc]
dir_back = all_dir_back[tfunc]

apply_instructions(dir_to_func)

while True:
	dfs = nx.dfs_postorder_nodes(g)
	not_vis = [x for x in dfs if g.out_degree(x) == 0 and not nodes[x].done]

	if not_vis == []:
		print 'Done'
		break

	st = nodes[not_vis[0]]
	current = st.id
	goal = 'down'
	
	#yn = raw_input("Explore from %d?" % current)
	#if yn.find('y') == -1:
	#	break
	
	apply_instructions(st.directions)

	while True:
		#print current
		try:
			until_header = read_header()	
		except Exception as e:
			print e
			print 'no header'
			apply_instructions(dir_back)
			break

		if goal == 'up' and current == 0:
			apply_instructions(dir_back)
			break

		line = io.recvline()
		if line.find('On the hall') != -1:
			t = 'code'
			runes = io.recvuntil('[ ')[:-2].replace(' ', '').replace('\n', '').decode('hex')
			missing = int(io.recvuntil(' ')[:-1]	)
			io.recvline()
		elif line.find('\\') != -1:
			t = 'down'
		elif line.find('/') != -1:
			t = 'up'	
		else:
			print line
			assert(False)

		if t == 'down':
			dirr += 'n'
			level_prompts += 1
			respline('Delve deeper? (y/n)', 'n')
		elif t == 'up':
			print 'Done %d' % current
			nodes[current].done = True
			apply_instructions(dir_back)
			break
		elif t == 'code':
			io.recvline()
			line = io.recvline()

			if not nodes[current].code:
				nodes[current].code = runes
				nodes[current].missing = missing
				nodes[current].level_prompts = level_prompts
				
			if goal == 'up':
				preds = list(g.predecessors(current))
				cand = [p for p in preds if nodes[p].id != None and nodes[p].code == runes]
				while len(cand) == 0 and len(preds) >= 1 and preds[0] != 0:
					c = preds[0]
					preds = list(g.predecessors(c))
					cand = [p for p in preds if nodes[p].id != None and nodes[p].code == runes]
				current = cand[0]
			
			if line.find('Make your choice') != -1:
				if not list(g.successors(current)):
					i1 = len(nodes)
					i2 = len(nodes) + 1
					left = Block(i1)
					right = Block(i2)
					nodes.append(left)
					nodes.append(right)
					g.add_node(i1)
					g.add_node(i2)
					g.add_edge(current, i1, dirr='left')
					g.add_edge(current, i2, dirr='right')

				succ = list(g.successors(current))
				while len(succ) == 1:
					current = succ[0]
					succ = list(g.successors(current))

				succ = sorted(succ, key=lambda x: 0 if g.edges[current, x]['dirr'] == 'left' else 1)
				left = nodes[succ[0]]
				right = nodes[succ[1]]
				left.directions = nodes[current].directions + dirr + '<' if not left.directions else left.directions
				right.directions = nodes[current].directions + dirr + '>' if not right.directions else right.directions

				if left == current:
					current.done = right.done
				if right == current:
					current.done = left.done

				if left.done and right.done:
					nodes[current].done = True
					goal = 'up'	
					io.sendline('^')
					line = io.recvuntil('\n')
					if line.find('rememberance') != -1:
						apply_instructions(dir_back)
						break
				elif not left.done:
					goal = 'down'
					current = left.id
					io.sendline('<')
				elif not right.done:
					goal = 'down'
					current = right.id
					io.sendline('>')
				dirr = ''
				level_prompts = 0
					
			elif line.find('In the faint') != -1:
				if not list(g.successors(current)):
					i1 = len(nodes)
					n = Block(i1)
					nodes.append(n)
					g.add_node(i1)
					g.add_edge(current, i1, dirr='left')
				n = list(g.successors(current))[0]
				nodes[n].directions = nodes[n].directions if nodes[n].directions else nodes[current].directions + dirr
				nodes[current].done = True
				dirr = ''
				level_prompts = 0 
				current = n
			elif line.find('---------------------'):
				if not nodes[current].code:
					nodes[current].code = runes
					nodes[current].missing = missing
				nodes[current].done = True
				apply_instructions(dir_back)
				break
			else:
				print line
				assert(False)

	heuristic2(nodes, g)
	heuristic3(nodes, g)

changed = True

while changed:
	changed = False
	changed = changed or heuristic1(nodes, g)
	changed = changed or heuristic2(nodes, g)
	changed = changed or heuristic3(nodes, g)
	changed = changed or heuristic4(nodes, g)
	changed = changed or heuristic5(nodes, g)
					
with open("nodes", 'wb') as f:
	f.write(dumps(nodes))
with open("graph", 'wb') as f:
	f.write(dumps(g))

io.close()
