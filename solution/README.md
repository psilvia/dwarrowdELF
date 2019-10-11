Solution
========

Read the writeup in the [official PTBCTF repo](https://github.com/Sin42/ptbctf).

Exploration
-----------

Use [this script](graph.py) to generate a representation of the CFG of a particular function. Then, plot the graph using
[this script](viewer.py). The reconstruction step is implemented in [puzzle.py](puzzle.py) for the _traverse_ function.
For any other function, you just need to replace some of the constraints.

Conquest
--------

The exploit script is [exp.py](exp.py).
