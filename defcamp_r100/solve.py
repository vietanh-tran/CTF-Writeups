#!/usr/bin/python3.8.2
import angr

r = angr.Project('r100')

desired_addr = 0x004007a1
wrong_addr = 0x00400790

entry_state = r.factory.entry_state(args=["./r.100"])
simulation = r.factory.simulation_manager(entry_state)
simulation.explore(find = desired_addr, avoid = wrong_addr)

solution = simulation.found[0].posix.dumps(0)
print (solution)
