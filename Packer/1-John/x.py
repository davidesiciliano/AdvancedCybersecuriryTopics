from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
p = process("./cookbook")
#p = remote("training.jinblack.it", 2017)
gdb.attach(p, '''
''')
context.log_level = 'debug'

raw_input()

p.interactive()