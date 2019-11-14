import angr
import claripy
import binascii
import IPython

to_reach = 0x0010167a
to_avoid = [0x001016e5,0x00101718]

p = angr.Project("./pnrg")
'''
sin = claripy.BVS("stdin", 0x8*8)
s = p.factory.entry_state(stdin=sin)
for x in sin.chop(8):
	s.solver.add(x >= 0x30)
	s.solver.add(x <= 0x78)
'''
#start = [claripy.BVV(b'0x')]
#number = [claripy.BVS('c%c' % i, 8) for i in range(8)]
#input_str = claripy.Concat(*start + number)
sin = claripy.BVS("stdin", 0xa*8)
s = p.factory.entry_state(stdin=sin)
for x in sin.chop(8):
	s.solver.add(x >= 0x30)
	s.solver.add(x <= 0x39)
#for n in number:
#	s.solver.add(n >= 0x30, n <= 0x78)
sm = p.factory.simgr(s)
sm.explore(find=to_reach, avoid=to_avoid)
sm.run()
if sm.found:
	print(sm.found[0].posix.dumps(0))
else:
	print "\nNON VA\n"

IPython.embed()