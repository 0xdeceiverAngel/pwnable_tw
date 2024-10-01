# Spirited Away


```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

```c=
int survey()
{
  char v1[56]; // [esp+10h] [ebp-E8h] BYREF
  size_t nbytes; // [esp+48h] [ebp-B0h]
  size_t v3; // [esp+4Ch] [ebp-ACh]
  char s[80]; // [esp+50h] [ebp-A8h] BYREF
  int v5; // [esp+A0h] [ebp-58h] BYREF
  void *nn_name_buf; // [esp+A4h] [ebp-54h]
  char v7[80]; // [esp+A8h] [ebp-50h] BYREF

  nbytes = 60;
  v3 = 80;
LABEL_2:
  memset(s, 0, sizeof(s));
  nn_name_buf = malloc(0x3Cu);
  printf("\nPlease enter your name: ");
  fflush(stdout);
  read(0, nn_name_buf, nbytes);
  printf("Please enter your age: ");
  fflush(stdout);
  __isoc99_scanf("%d", &v5);
  printf("Why did you came to see this movie? ");
  fflush(stdout);
  read(0, v7, v3);
  fflush(stdout);
  printf("Please enter your comment: ");
  fflush(stdout);
  read(0, s, nbytes);
  ++cnt;
  printf("Name: %s\n", (const char *)nn_name_buf);
  printf("Age: %d\n", v5);
  printf("Reason: %s\n", v7);
  printf("Comment: %s\n\n", s);
  fflush(stdout);
  sprintf(v1, "%d comment so far. We will review them as soon as we can", cnt);
  puts(v1);
  puts(&::s);
  fflush(stdout);
  if ( cnt > 199 )
  {
    puts("200 comments is enough!");
    fflush(stdout);
    exit(0);
  }
  while ( 1 )
  {
    printf("Would you like to leave another comment? <y/n>: ");
    fflush(stdout);
    read(0, &choice, 3u);
    if ( choice == 89 || choice == 121 )
    {
      free(nn_name_buf);
      goto LABEL_2;
    }
    if ( choice == 78 || choice == 110 )
      break;
    puts("Wrong choice.");
    fflush(stdout);
  }
  puts("Bye!");
  return fflush(stdout);
}
```

read 函數固定大小，不會 null 截斷，可以read 不全部填，print local var 可能可以 leak 

有機會可以一次就拿到 libc and stack

cnt 在 bss 


len(" comment so far. We will review them as soon as we can") = 54
v1 只有 56

所以當 cnt 超過三位數就會 overflow 蓋到 nbytes

nbytes 從 60 0x3c –> 110 0x6e 'n'

read with size nbytes 可以造成 nn_name_buf 和 comment overflow

可以從 comment overflow name_buf 造成任意 free

name_buf 可以蓋成 stack 位置，free name_buf 再 alloc 出來 ，再去寫該塊位置成功 stack overflow ret addr

先 debug leak libc and stack
在 stack 偽造 chunk 任意 free  再 alloc 拿 stack
再去寫入 rop 或 one gadget

~~理論上應該從 name_buf 可以蓋到 ret addr， one gadget 跳 shell 但是需要 libc base~~
不行，因為是 malloc 出來的 heap 位置





From gpt
```
小結
會自動添加 NULL 終止符的函數：

fgets()
getline()
scanf()（當讀取字符串時）
sscanf()（當讀取字符串時）
gets()（已棄用，危險）
不會自動添加 NULL 終止符的函數（需要手動處理）：

read()
getchar()
getch() / getche()
選擇這些函數時，特別要注意是否需要手動處理 NULL 終止符，尤其是使用低級 I/O 函數如 read() 的時候。

```





```
>為何 pwn stack overflow 蓋掉 ret address 呼叫 system 要在參數中間加入 padding 
>p32(system_addr) + p32(0xdeadbeef) + p32(bin_sh)

在利用「堆疊溢出」（stack overflow）來進行「`system()` 函數呼叫」的攻擊中，加入一個無用的填充數據（如 `0xdeadbeef`）是因為「**堆疊的結構與系統調用的參數傳遞方式**」有關。具體來說，這是由於函數調用時，堆棧的數據排列方式，特別是 **`system()` 函數遵循的調用約定（calling convention）**。

### 背景：
當利用堆疊溢出覆蓋返回地址時，通常攻擊者會將目標設為某個已知的函數地址，比如 `system()` 函數。攻擊的目的是執行 `system("/bin/sh")`，從而打開一個 shell。然而，執行這樣的操作時，必須遵循調用系統函數的約定，即如何將參數傳遞給 `system()` 函數。

### 參數傳遞與調用約定：
在常見的 **CDECL** 或 **cdecl** 調用約定中（例如在 32 位系統上），函數參數是按以下順序壓入堆疊的：
1. **函數的參數**（從右到左）。
2. **返回地址**（即將控制權交還給下一條指令的地址，當前堆疊幀的上層返回地址）。
3. **保存的寄存器或其他信息**（如 `ebp`）。

具體到 `system()` 函數，它的參數傳遞遵循這一標準：
- `system()` 函數只需要一個參數，即 `/bin/sh` 的字符串地址。
- 返回地址需要存在堆棧上，這個返回地址指向下一個要執行的指令（在攻擊中，你可以放一個假地址，如 `0xdeadbeef`，因為我們並不打算返回到有效的地址）。

### 為什麼需要填充（Padding）？
在覆蓋返回地址時，攻擊者通常會寫入三個值：
1. **`system()` 函數的地址**：這是你希望程序跳轉並執行的地方。
2. **假返回地址（padding）**：這是用來佔據 `system()` 函數執行完畢後返回的地址位置，但我們不打算返回到任何有效的地方，所以這可以是任意值（如 `0xdeadbeef`）。在一些情況下，這一值可以完全無用，但必須要填充，因為調用約定要求堆疊中需要有返回地址的位置。
3. **參數 `/bin/sh` 的地址**：這是傳遞給 `system()` 函數的參數，用於打開 shell。

### 攻擊鏈的完整結構：
在構建 exploit payload 時，假設你已經覆蓋了返回地址，並且將其指向 `system()` 函數，那麼你需要遵循調用約定來傳遞參數。因此，當你利用堆疊溢出攻擊 `system("/bin/sh")` 時，payload 的結構如下：

```plaintext
[p32(system_addr)] + [p32(fake_return_address)] + [p32(bin_sh_addr)]
```

- **`p32(system_addr)`**：`system()` 函數的地址。
- **`p32(fake_return_address)`**：填充值（通常是無用的地址，比如 `0xdeadbeef`，因為 `system()` 函數執行完後，我們不需要返回到有效的地方）。
- **`p32(bin_sh_addr)`**：字符串 `/bin/sh` 的地址，這是傳遞給 `system()` 函數的參數。

### 具體步驟：
1. 當覆蓋返回地址後，程序的控制權將跳轉到 `system()` 函數的地址。
2. 根據調用約定，`system()` 函數會從堆疊中取出**下一個值**作為返回地址，這就是你提供的 `0xdeadbeef`（雖然這不會被實際用到，因為我們不需要 `system()` 函數返回任何東西）。
3. 然後，`system()` 會從堆棧中取出第三個值作為它的參數，這個參數就是 `/bin/sh` 字符串的地址。

### 為什麼不能省略填充？
調用約定要求每個函數的返回地址和參數都要按正確的順序排列在堆疊上。如果你跳過了返回地址的填充，`system()` 函數將錯誤地將 `/bin/sh` 的地址當作返回地址，而不會正確識別出參數，從而導致錯誤或崩潰。

### 小結：
- 在構建 `system()` 調用的 exploit 時，**`p32(system_addr)`** 是 `system()` 函數的地址。
- **`p32(0xdeadbeef)`** 是一個無用的填充（假返回地址），因為 `system()` 調用約定需要有一個返回地址。
- **`p32(bin_sh)`** 是 `/bin/sh` 字符串的地址，作為參數傳遞給 `system()` 函數。

```




>FLAG{Wh4t_1s_y0ur_sp1r1t_1n_pWn}