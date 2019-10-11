import networkx as nx
from pwn import disasm, context
from networkx.drawing.nx_agraph import graphviz_layout, write_dot
from pickle import dumps, loads
import matplotlib.pyplot as plt
from subprocess import check_output
from block import Block


with open('nodes', 'rb') as f:
	nodes = loads(f.read())
with open('graph', 'rb') as f:
	g = loads(f.read())

'''
for n in nodes:
	if n.id != None:
		print(n)
'''

labeldict = {}
for n in nodes:
	if n.id != None:
		labeldict[n.id] = repr(n) #n.smallformat()

g = nx.relabel_nodes(g, labeldict)
write_dot(g, 'graph.dot')

with open('graph.png', 'wb') as f:
	out = check_output(['dot', '-Tpng', 'graph.dot'])
	f.write(out)
