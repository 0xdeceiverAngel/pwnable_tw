# start
第一題 就看了很久QQ

原本看checksec 沒有NX

但是進去gdb 裡看 卻有NX

還有 i386的 syscall 跟 x86 不一樣RRR

搞我阿

writeup：

```asm=
[0x08048060]> pdf
            ;-- section..text:
            ;-- _start:
/ (fcn) entry0 61
|   entry0 ();
|           0x08048060      54             push esp                    ; [01] -r-x section size 67 named .text
|           0x08048061      689d800408     push loc._exit              ; 0x804809d ; "\1\xc0@\u0340\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
|           0x08048066      31c0           xor eax, eax
|           0x08048068      31db           xor ebx, ebx
|           0x0804806a      31c9           xor ecx, ecx
|           0x0804806c      31d2           xor edx, edx
|           0x0804806e      684354463a     push 0x3a465443             ; 'CTF:'
|           0x08048073      6874686520     push 0x20656874             ; 'the '
|           0x08048078      6861727420     push 0x20747261             ; 'art '
|           0x0804807d      6873207374     push 0x74732073             ; 's st'
|           0x08048082      684c657427     push 0x2774654c             ; 'Let''
|           0x08048087      89e1           mov ecx, esp
|           0x08048089      b214           mov dl, 0x14                ; 20
|           0x0804808b      b301           mov bl, 1
|           0x0804808d      b004           mov al, 4
|           0x0804808f      cd80           int 0x80
|           0x08048091      31db           xor ebx, ebx
|           0x08048093      b23c           mov dl, 0x3c                ; '<' ; 60
|           0x08048095      b003           mov al, 3
|           0x08048097      cd80           int 0x80
|           0x08048099      83c414         add esp, 0x14
\           0x0804809c      c3             ret

```
因為有NX  所以要leak位置

第一次 輸入蓋過ret 返回  下面J個 addr
```=
0x08048087      89e1           mov ecx, esp
```
因為已經走過一次了 所以 esp 會是紀錄到 stack的最高(?)位置

然後靠 mov ecx, esp 搞出 esp 的位置

恩對 噴出來之後 就再次輸入

這次就 擺上拉機+ret的位置搞好+塞入shellcode

然後它就會跳上 ret 再轉上 shellcode
