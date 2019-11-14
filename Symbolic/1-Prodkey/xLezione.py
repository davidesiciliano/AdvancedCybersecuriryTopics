import angr

p = angr.Project("./prodkey")

s = p.factory.entry_state()
sm = p.factory.simgr(s)

#addr is address we want to reach, addr1 and addr2 the addresses we want to avoid
sm.explore(find=addr, avoid=[addr1, addr2])
#this will return some string with no printable value
#we need to add some constraints to obtain printable ones

import claripy
sin = claripy.BVS("stdin", 0x1e*8)
#sin = claripy.BVS("stdin", 0x1e*8, explicit_name = True) will regenerate always the same string
s = p.factory.entry_state()
for x in sin.chop(8):
	s.solver.add(x > 0x20)
	s.solver.add(x < ord('z'))
sm = p.factory.simgr(s)
sm.explore(find=addr, avoid=[addr1, addr2])

f = sm.found[0] --> salva in f la roba trovata
f.solver.eval(sin) --> stampa tutta la roba trovata 


'''
dopo devo fare
	sm --> per vedere se ha trovato qualcosa
	f = sm.found[0] --> salva in f la roba trovata
	f.solver.eval(sin) --> stampa tutta la roba trovata 
	x = "%x" % roba trovata --> per convertire in stringa
	import binascii
	print(binascii.a2b_hex(x))
'''

import IPython
IPython.embed()