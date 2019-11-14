import angr
import claripy
import binascii
import IPython

p = angr.Project("./prodkey")
sin = claripy.BVS("stdin", 0x1e*8)
s = p.factory.entry_state(stdin=sin)
for x in sin.chop(8):
	s.solver.add(x > 0x21)
	s.solver.add(x <= ord('z'))
sm = p.factory.simgr(s)
sm.explore(find=0x00400deb, avoid=[0x00400df2, 0x00400dfb])
sm.run()
f = sm.found[0]

IPython.embed()

#poi uso comando 
#f.posix.dumps(0)
#per printare la prodkey trovata