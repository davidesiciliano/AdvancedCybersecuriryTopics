import angr
import claripy
import IPython

proj = angr.Project("./pnrg", load_options={'auto_load_libs': False})

to_reach = 0x0010167a
to_avoid = [0x001016e5,0x00101718]

cfg = proj.analyses.CFGFast()
fun = proj.kb.functions.get("main")
addr_main = fun.startpoint.addr

sin = claripy.BVS("stdin", 0xa*8)
state = proj.factory.blank_state(stdin=sin)
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x0010167a, avoid=0x001016e5)

if len(simgr.found) > 0:
	print "\nOK\n"
else:
	print "\nNON VA\n"

IPython.embed()