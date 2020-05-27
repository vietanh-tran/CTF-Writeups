#!/usr/bin/python3.8.2
import angr
import claripy

r = angr.Project('fairlight')

desired_addr = 0x00401a73
wrong_addr = 0x0040074d

input = claripy.BVS("inp", 0xe*8)
entry_state = r.factory.entry_state(args=["./fairlight", input])
simulation = r.factory.simulation_manager(entry_state)
simulation.explore(find = desired_addr, avoid = wrong_addr)

solution = simulation.found[0]
print (solution.solver.eval(input, cast_to=bytes))
