import os
import networkx as nx
from pwn import disasm, context
from pickle import dumps, loads
from itertools import product
from block import Block

context.arch = 'amd64'

tfunc = None

def merge_init(tf):
	global tfunc
	tfunc = tf

def remove_node(nodes, g, node):
	if len(list(g.predecessors(node))):
		return

	succs = list(g.successors(node))
	nodes[node].id = None
	g.remove_node(node)
	for s in succs:
		if nodes[s].id != None and s != node:
			remove_node(nodes, g, s)

def can_be_merged(nodes, g, id1, id2):
	# check successors
	left = set(p for p in g.successors(id1) if g.edges[id1, p]['dirr'] == 'left')
	left = left.union(p for p in g.successors(id2) if g.edges[id2, p]['dirr'] == 'left')
	right = set(p for p in g.successors(id1) if g.edges[id1, p]['dirr'] == 'right')
	right = right.union(p for p in g.successors(id2) if g.edges[id2, p]['dirr'] == 'right')

	return len(left) <= 1 and len(right) <= 1

# replace occurences of id1
def merge_nodes(nodes, g, id1, id2):
	bl1 = nodes[id1]
	preds = list(g.predecessors(id1))
	for p in preds:
		succs = list(g.successors(p))
		other = None
		dirr = g.edges[p, id1]['dirr']
		g.remove_edge(p, id1)
		g.add_edge(p, id2, dirr=dirr)

	remove_node(nodes, g, id1)
	bl1.id = None

# Heuristic 1: if one child node includes the other, remove the duplicate part
def heuristic1(nodes, g):
	changes = 0

	for n in nodes:
		if n.id == None:
			continue

		succ = list(g.successors(n.id))
		if len(succ) < 2:
			continue
		left = succ[0]
		right = succ[1]
		lb = nodes[left]
		rb = nodes[right]

		if not lb.code or not rb.code:
			continue

		if lb.code.find(rb.code) != -1 and len(rb.code) > 1:
			idx = lb.code.find(rb.code)
			if idx + len(rb.code) != len(lb.code):
				continue

			print 'H1: split %d' % left
			lb.code = lb.code[:idx]
			lb.missing = 0
			g.remove_edges_from(g.out_edges(left))
			g.add_edge(left, right, dirr='left')

			changes += 1

		elif rb.code.find(lb.code) != -1 and len(lb.code) > 1:
			idx = rb.code.find(lb.code)
			if idx + len(lb.code) != len(rb.code):
				continue

			print 'H1: split %d' % right
			rb.code = rb.code[:idx]
			rb.missing = 0
			g.remove_edges_from(g.out_edges(right))
			g.add_edge(right, left, dirr='left')

			changes += 1
	return changes

# Heuristic 2: if a node points to an identical node, merge them
def heuristic2(nodes, g):
	changes = 0

	for n in nodes:
		if n.id == None:
			continue

		succ = list(g.successors(n.id))
		if len(succ) < 2:
			continue

		done = True
		for s in succ:
			sb = nodes[s]

			if sb.code and sb.code == n.code and n.id != s:
				print 'H2: merge %d into %d' % (s, n.id)
				dirr = g.edges[n.id, s]['dirr']
				g.remove_edge(n.id, s)
				g.add_edge(n.id, n.id, dirr=dirr)
				remove_node(nodes, g, s)

				changes += 1
			else:
				done = done and sb.done
		n.done = done

	return changes

def choose_merge_order(nodes, x, y):
	xb = nodes[x]
	yb = nodes[y]

	if xb.done and not yb.done:
		victim = y
		target = x
	elif yb.done and not xb.done:
		victim = x
		target = y
	else:
		victim = max(x, y)
		target = min(x, y)
	return victim, target

# Heuristic 3: merge nodes with identical code and indentical successors
def heuristic3(nodes, g):
	global tfunc

	changes = 0
	ids = [i for i in range(len(nodes)) if nodes[i].id != None]
	for (x, y) in product(ids, ids):
		xb = nodes[x]
		yb = nodes[y]
		if xb.id == None or yb.id == None or x == y or not xb.code or not yb.code:
			continue

		blacklist = [240, 242, 763, 468, 470, 988]
		if tfunc == 'traverse' and (x in blacklist or y in blacklist) and set([x, y]) != set([468, 470]):
			continue

		if xb.code == yb.code and xb.done == True and yb.done == True \
			and list(g.successors(x)) == list(g.successors(y)):
			victim, target = choose_merge_order(nodes, x, y)
			print 'H3: merge %d into %d' % (victim, target)
			merge_nodes(nodes, g, victim, target)

			changes += 1
		elif xb.code == yb.code :
			#if (467 in g.predecessors(x) or 467 in g.predecessors(y)) and 369 in [x, y]:
			#	print x, y, list(g.predecessors(x)), list(g.predecessors(y))

			succx = list(g.successors(x))
			succy = list(g.successors(y))
			if len(succx) != len(succy):
				continue

			#if set(nodes[succxi].code for succxi in succx) == set(nodes[succyi].code for succyi in succy):
			if nodes[succx[0]].code and nodes[succy[0]].code and nodes[succx[0]].code == nodes[succy[0]].code:
				victim, target = choose_merge_order(nodes, x, y)
				print 'H3: merge %d into %d' % (victim, target)
				merge_nodes(nodes, g, victim, target)

				changes += 1

	return changes

# Heuristic 4: if two nodes have common successors and one contains the other, split and merge
def heuristic4(nodes, g):
	global tfunc
	changes = 0

	for n in nodes:
		if n.id == None:
			continue

		preds = list(g.predecessors(n.id))
		if len(preds) < 2:
			continue

		for x, y in product(preds, preds):
			xb = nodes[x]
			yb = nodes[y]

			if x == y or not xb.code or not yb.code or ((len(xb.code) <= 2 or len(yb.code) <= 2) and ([x, y] != [468, 471] or tfunc != 'traverse')):
				continue

			blacklist = [243]
			if list(g.successors(x)) != list(g.successors(y)):
				continue

			if tfunc == 'traverse' and (x in blacklist or y in blacklist):
				continue

			if xb.code.find(yb.code) != -1:
				idx = xb.code.find(yb.code)
				if idx + len(yb.code) != len(xb.code) or len(xb.code) == len(yb.code):
					continue

				print 'H4: split %d, contains %d' % (x, y)
				xb.code = xb.code[:idx]
				xb.missing = 0
				g.remove_edges_from(g.out_edges(x))
				g.add_edge(x, y, dirr='left')

				changes += 1

	return changes

# Heuristic 5: if two nodes with common successors end in common code, move it to a separate node
def heuristic5(nodes, g):
	ids = [i for i in range(len(nodes)) if nodes[i].id != None and nodes[i].code]
	changes = 0

	for x in ids:
		succx = list(g.successors(x))
		for y in ids:
			succy = list(g.successors(y))
			if x == y or len(succx) or len(succy):#set(succx) != set(succy):
				continue

			codex = nodes[x].code
			codey = nodes[y].code
			suffix = os.path.commonprefix([codex[::-1], codey[::-1]])[::-1]
			if suffix and nodes[x].missing == nodes[y].missing \
				and (len(suffix) > 3 or suffix[-1] == '\xc3') \
				and len(codex) != len(codey):
				target = x if len(suffix) == len(codex) else y	
				other = y if target == x else x
				
				print 'H5: split %d from %d' % (target, other)
				g.remove_edges_from((other, s) for s in g.successors(other))	
				g.add_edge(other, target, dirr='left')

				nodes[other].code = nodes[other].code[:-len(suffix)]
				nodes[other].missing = 0
				nodes[target].code = suffix

				changes += 1

	return changes

def reset_done(nodes, g):
	# Reset 'done' flag
	for n in nodes:
		if n.id != None and n.code:
			n.done = all(nodes[x].done for x in g.successors(n.id))

	# Set done flag for circular loops
	for n in nodes:
		if n.id != None:
			loop = False
			succ = list(g.successors(n.id))
			if len(succ) != 2:
				continue
			if n.id in g.successors(succ[0]):
				n.done = nodes[succ[1]].done
			elif n.id in g.successors(succ[1]):
				n.done = nodes[succ[0]].done
